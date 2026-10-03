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
    ULTRON_DATA_DIR file vault for uploads (default ~/ultron-data)
"""

import hmac
import os
import re
import socket
import sqlite3
import threading
import time
from contextlib import asynccontextmanager
from typing import Any, Dict, List

import httpx
from dotenv import load_dotenv
from fastapi import Depends, FastAPI, File, HTTPException, Security, UploadFile
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


# ---------------------------------------------------------------- port forward
# Local TCP relay: 127.0.0.1:<local_port> -> <target_host>:<target_port>.
# The listening side binds to localhost ONLY — a forwarded port is never
# exposed to the network, only to this machine. For reaching cameras and
# devices you own without punching holes in anything.

_forwards = {}  # local_port -> {stop, thread, target_host, target_port}


def _pump(src, dst, stop):
    try:
        while not stop.is_set():
            data = src.recv(65536)
            if not data:
                break
            dst.sendall(data)
    except OSError:
        pass


def _handle_client(client, target_host, target_port, stop):
    try:
        upstream = socket.create_connection((target_host, target_port),
                                            timeout=10)
    except OSError:
        try:
            client.close()
        except OSError:
            pass
        return
    t1 = threading.Thread(target=_pump, args=(client, upstream, stop),
                          daemon=True)
    t2 = threading.Thread(target=_pump, args=(upstream, client, stop),
                          daemon=True)
    t1.start()
    t2.start()
    t1.join()
    t2.join()
    for s in (client, upstream):
        try:
            s.close()
        except OSError:
            pass


def _serve_forward(srv, target_host, target_port, stop):
    srv.listen(20)
    srv.settimeout(1.0)
    while not stop.is_set():
        try:
            client, _ = srv.accept()
        except socket.timeout:
            continue
        except OSError:
            break
        threading.Thread(target=_handle_client,
                         args=(client, target_host, target_port, stop),
                         daemon=True).start()
    try:
        srv.close()
    except OSError:
        pass


def _valid_port(p):
    return isinstance(p, int) and 1 <= p <= 65535


class PortForward(BaseModel):
    target_host: str   # camera / device address, e.g. "192.168.1.50"
    target_port: int   # its port, e.g. 554 for RTSP
    local_port: int    # local port you open, e.g. 8554


@app.post("/port-forward", dependencies=[Depends(require_permission)])
async def port_forward_start(pf: PortForward):
    """Open 127.0.0.1:<local_port> relaying to <target_host>:<target_port>."""
    host = pf.target_host.strip()
    if not host:
        raise HTTPException(status_code=400,
                            detail="target_host is required.")
    if not _valid_port(pf.target_port) or not _valid_port(pf.local_port):
        raise HTTPException(status_code=400,
                            detail="Ports must be 1-65535.")
    if pf.local_port == 8000:
        raise HTTPException(status_code=400,
                            detail="Cannot forward the server's own port.")
    if pf.local_port in _forwards:
        raise HTTPException(status_code=409,
                            detail=f"Port {pf.local_port} already forwarded.")
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    try:
        srv.bind(("127.0.0.1", pf.local_port))
    except OSError as e:
        srv.close()
        raise HTTPException(status_code=409,
                            detail=f"Cannot bind local port "
                                   f"{pf.local_port}: {e}")
    stop = threading.Event()
    t = threading.Thread(target=_serve_forward,
                         args=(srv, host, pf.target_port, stop),
                         daemon=True)
    t.start()
    _forwards[pf.local_port] = {"stop": stop, "thread": t,
                                "target_host": host,
                                "target_port": pf.target_port}
    return {"status": "forwarding",
            "listen": f"127.0.0.1:{pf.local_port}",
            "target": f"{host}:{pf.target_port}"}


@app.get("/port-forwards", dependencies=[Depends(require_permission)])
async def port_forward_list():
    """List active forwards."""
    return {"forwards": [
        {"local_port": p, "listen": f"127.0.0.1:{p}",
         "target": f"{v['target_host']}:{v['target_port']}",
         "alive": v["thread"].is_alive()}
        for p, v in _forwards.items()]}


@app.delete("/port-forward/{local_port}",
            dependencies=[Depends(require_permission)])
async def port_forward_stop(local_port: int):
    """Stop a forward."""
    fw = _forwards.pop(local_port, None)
    if fw is None:
        raise HTTPException(status_code=404,
                            detail="No forward on that port.")
    fw["stop"].set()
    return {"status": "stopped", "local_port": local_port}


# ---- file vault + database query (permission-gated) ----
# Upload intelligence databases / files to the server, list them, run
# read-only SQL against uploaded SQLite databases, delete them.

DATA_DIR = os.environ.get("ULTRON_DATA_DIR",
                           os.path.expanduser("~/ultron-data"))
os.makedirs(DATA_DIR, exist_ok=True)
MAX_UPLOAD = 100 * 1024 * 1024  # 100 MB

_SAFE_NAME = re.compile(r"[^A-Za-z0-9._-]")


def _safe_name(name):
    name = os.path.basename(name or "upload.bin")
    name = _SAFE_NAME.sub("_", name).strip("._") or "upload.bin"
    return name[:120]


class Query(BaseModel):
    db: str
    sql: str


@app.post("/upload", dependencies=[Depends(require_permission)])
async def upload_file(file: UploadFile = File(...)):
    """Store an uploaded file in the vault (100 MB max)."""
    dest = os.path.join(DATA_DIR, _safe_name(file.filename))
    if not os.path.abspath(dest).startswith(os.path.abspath(DATA_DIR)):
        raise HTTPException(status_code=400, detail="Bad filename.")
    size = 0
    try:
        with open(dest, "wb") as f:
            while True:
                chunk = await file.read(1024 * 256)
                if not chunk:
                    break
                size += len(chunk)
                if size > MAX_UPLOAD:
                    raise HTTPException(status_code=413,
                                        detail="File too large (100 MB max).")
                f.write(chunk)
    except HTTPException:
        if os.path.exists(dest):
            os.unlink(dest)
        raise
    return {"status": "stored", "name": os.path.basename(dest),
            "bytes": size}


@app.get("/files", dependencies=[Depends(require_permission)])
async def list_files():
    """List files in the vault."""
    out = []
    for n in sorted(os.listdir(DATA_DIR)):
        p = os.path.join(DATA_DIR, n)
        if os.path.isfile(p):
            st = os.stat(p)
            out.append({"name": n, "bytes": st.st_size,
                        "modified": int(st.st_mtime)})
    return {"files": out, "dir": DATA_DIR}


@app.delete("/files/{name}", dependencies=[Depends(require_permission)])
async def delete_file(name: str):
    """Delete a file from the vault."""
    dest = os.path.join(DATA_DIR, _safe_name(name))
    if not os.path.isfile(dest):
        raise HTTPException(status_code=404, detail="No such file.")
    os.unlink(dest)
    return {"status": "deleted", "name": os.path.basename(dest)}


@app.post("/query", dependencies=[Depends(require_permission)])
async def query_db(q: Query):
    """Read-only SQL against an uploaded SQLite database."""
    if not q.sql.strip().lower().startswith("select"):
        raise HTTPException(status_code=400,
                            detail="Read-only: only SELECT queries allowed.")
    dest = os.path.join(DATA_DIR, _safe_name(q.db))
    if not os.path.isfile(dest):
        raise HTTPException(status_code=404,
                            detail="No such database. Upload it first.")
    try:
        con = sqlite3.connect("file:%s?mode=ro" % dest, uri=True)
        con.row_factory = sqlite3.Row
        cur = con.execute(q.sql)
        rows = [dict(r) for r in cur.fetchmany(200)]
        cols = [d[0] for d in cur.description] if cur.description else []
        con.close()
    except sqlite3.Error as e:
        raise HTTPException(status_code=400, detail="SQL error: %s" % e)
    return {"columns": cols, "rows": rows,
            "truncated": len(rows) == 200}


# ---- camera watchdog (defensive: YOUR cameras only) ----
# Registers cameras you own and TCP-checks each one every 5 seconds.
# This is monitoring, not intrusion: plain connectivity checks, no logins,
# no credentials, no stream access. State changes (online<->OFFLINE) are
# timestamped into an event log. Re-register after a server restart.

WATCH_INTERVAL = 5  # seconds between sweeps
WATCH_TIMEOUT = 3   # seconds per connect attempt

_watch = {"cameras": [], "status": {}, "events": [],
          "running": False, "thread": None, "lock": threading.Lock()}


def _watch_probe(host, port):
    start = time.time()
    try:
        s = socket.create_connection((host, port), timeout=WATCH_TIMEOUT)
        s.close()
        return True, int((time.time() - start) * 1000)
    except Exception:
        return False, None


def _watch_loop():
    while True:
        with _watch["lock"]:
            if not _watch["running"]:
                break
            cams = list(_watch["cameras"])
        for cam in cams:
            ok, ms = _watch_probe(cam["host"], cam["port"])
            now = int(time.time())
            with _watch["lock"]:
                st = _watch["status"].get(cam["name"], {})
                prev = st.get("online")
                st.update({"online": ok, "latency_ms": ms,
                           "last_check": now,
                           "host": cam["host"], "port": cam["port"]})
                if prev is None or prev != ok:
                    st["last_change"] = now
                    if prev is not None:
                        _watch["events"].append(
                            {"time": now, "camera": cam["name"],
                             "event": "online" if ok else "OFFLINE"})
                        _watch["events"] = _watch["events"][-50:]
                _watch["status"][cam["name"]] = st
        for _ in range(WATCH_INTERVAL * 2):  # prompt stop
            with _watch["lock"]:
                if not _watch["running"]:
                    return
            time.sleep(0.5)


def _watch_stop():
    with _watch["lock"]:
        _watch["running"] = False
        t = _watch["thread"]
    if t and t.is_alive():
        t.join(timeout=5)
    with _watch["lock"]:
        _watch["thread"] = None


class WatchCamera(BaseModel):
    name: str                    # label, e.g. "front-door"
    host: str                    # camera address, e.g. "192.168.1.50"
    port: int                    # its port, e.g. 554


class WatchList(BaseModel):
    cameras: List[WatchCamera]


@app.post("/watch", dependencies=[Depends(require_permission)])
async def watch_start(wl: WatchList):
    """Register YOUR cameras and start the 5-second watchdog."""
    cams = []
    seen = set()
    for c in wl.cameras[:50]:
        name = c.name.strip()[:60]
        host = c.host.strip()
        if not name or not host or name in seen:
            raise HTTPException(status_code=400,
                                detail="Each camera needs a unique name and host.")
        if not _valid_port(c.port):
            raise HTTPException(status_code=400,
                                detail="Port %r out of range." % c.port)
        seen.add(name)
        cams.append({"name": name, "host": host, "port": c.port})
    if not cams:
        raise HTTPException(status_code=400,
                            detail="No cameras given.")
    _watch_stop()
    with _watch["lock"]:
        _watch["cameras"] = cams
        _watch["status"] = {}
        _watch["events"] = []
        _watch["running"] = True
        t = threading.Thread(target=_watch_loop, daemon=True)
        _watch["thread"] = t
        t.start()
    return {"status": "watching", "cameras": len(cams),
            "interval_s": WATCH_INTERVAL}


@app.get("/watch", dependencies=[Depends(require_permission)])
async def watch_status():
    """Current watchdog state + recent online/OFFLINE transitions."""
    with _watch["lock"]:
        return {"running": _watch["running"],
                "interval_s": WATCH_INTERVAL,
                "cameras": dict(_watch["status"]),
                "events": list(_watch["events"])}


@app.delete("/watch", dependencies=[Depends(require_permission)])
async def watch_stop():
    """Stop the watchdog."""
    _watch_stop()
    return {"status": "stopped"}


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
