import asyncio
import hashlib
import json
import logging
import os
import queue
import re
import secrets
import shutil
import threading
import time
import uuid
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI, File, Form, HTTPException, Request, UploadFile, Depends
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field
from starlette.middleware.trustedhost import TrustedHostMiddleware

from lab.config import SETTINGS, PROFILES, PROFILE_MAP
from lab.store import Store, TERMINAL, utcnow
from lab.worker import Worker, public_job, redacted_share
from lab.integrations import capabilities as external_capabilities
from lab.report import render_pdf
from lab.http_limits import BodyLimitMiddleware
from lab.sharing import public_origin as share_origin
from lab.runtime_status import privacy_proof_summary, runtime_status

COOKIE = "sandbox_session"

class SessionRequest(BaseModel):
    token: str = Field(min_length=1, max_length=256)

class ShareRequest(BaseModel):
    hours: int = Field(default=24, ge=1, le=168)


def create_app(settings=SETTINGS, start_worker=True):
    settings.prepare()
    store = Store(settings.db_path)
    worker = Worker(settings, store)
    sessions = {}
    login_attempts = {}
    upload_lock = asyncio.Lock()
    upload_inflight = 0
    pdf_lock = threading.Lock()

    @asynccontextmanager
    async def lifespan(app):
        if start_worker:
            worker.start()
        yield
        if start_worker:
            await asyncio.to_thread(worker.close)

    app = FastAPI(title="BLACKSITE", version="0.1.0", lifespan=lifespan, docs_url=None, redoc_url=None, openapi_url=None)
    app.add_middleware(BodyLimitMiddleware, max_upload=settings.max_upload)
    app.add_middleware(TrustedHostMiddleware, allowed_hosts=["localhost", "127.0.0.1", "[::1]", "testserver"])
    app.state.store = store
    app.state.worker = worker
    app.state.settings = settings

    def is_authenticated(request):
        auth = request.headers.get("authorization", "")
        if auth.startswith("Bearer ") and secrets.compare_digest(auth[7:], settings.token):
            return True
        cookie = request.cookies.get(COOKIE, "")
        if len(cookie) > 128:
            return False
        digest = hashlib.sha256(cookie.encode()).hexdigest()
        expiry = sessions.get(digest, 0)
        if expiry <= time.time():
            sessions.pop(digest, None)
            return False
        return True

    def authenticated(request: Request):
        if not is_authenticated(request):
            raise HTTPException(401, "Token richiesto")

    @app.middleware("http")
    async def security(request, call_next):
        nonlocal upload_inflight
        origin = request.headers.get("origin")
        expected = f"{request.url.scheme}://{request.headers.get('host', '')}"
        if request.method in {"POST", "PUT", "PATCH", "DELETE"}:
            if origin and origin != expected:
                raise_error = True
            else:
                raise_error = not origin and not request.headers.get("authorization", "").startswith("Bearer ")
            if raise_error:
                from fastapi.responses import JSONResponse
                return JSONResponse({"detail": "Origine non consentita: usa pagina locale o Bearer token"}, status_code=403)
        reserved = False
        if request.method == "POST" and request.url.path == "/api/jobs":
            from fastapi.responses import JSONResponse
            if not is_authenticated(request):
                return JSONResponse({"detail": "Token richiesto"}, status_code=401)
            if upload_inflight >= 2 or store.pending_count() >= settings.max_queue:
                return JSONResponse({"detail": "Coda o ingressi upload occupati"}, status_code=429)
            if shutil.disk_usage(settings.data).free < settings.max_upload + 8 * 1024 * 1024 * 1024:
                return JSONResponse({"detail": "Spazio insufficiente"}, status_code=507)
            # Reserve before FastAPI request.form(): dependencies run after body parsing.
            upload_inflight += 1
            reserved = True
        try:
            response = await call_next(request)
        finally:
            if reserved:
                upload_inflight -= 1
        response.headers["Content-Security-Policy"] = "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; connect-src 'self'; object-src 'none'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'"
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["Referrer-Policy"] = "no-referrer"
        response.headers["Cache-Control"] = "no-store"
        response.headers["Permissions-Policy"] = "camera=(), microphone=(), geolocation=()"
        return response

    @app.get("/api/health")
    async def health():
        return {"status": "ok", "service": "BLACKSITE"}

    @app.get("/api/session")
    async def session_status(request: Request):
        return {"authenticated": is_authenticated(request)}

    @app.post("/api/session")
    async def session(payload: SessionRequest, request: Request):
        host = request.client.host if request.client else "local"
        now = time.monotonic()
        attempts = [stamp for stamp in login_attempts.get(host, []) if now - stamp < 60]
        if len(attempts) >= 10:
            raise HTTPException(429, "Troppi tentativi: attendi un minuto")
        if not secrets.compare_digest(payload.token, settings.token):
            login_attempts[host] = attempts + [now]
            await asyncio.sleep(0.15)
            raise HTTPException(401, "Token non valido")
        login_attempts.pop(host, None)
        sessions.clear() if len(sessions) > 256 else None
        cookie = secrets.token_urlsafe(32)
        sessions[hashlib.sha256(cookie.encode()).hexdigest()] = time.time() + 12 * 3600
        from fastapi.responses import JSONResponse
        response = JSONResponse({"authenticated": True})
        response.set_cookie(COOKIE, cookie, max_age=12 * 3600, httponly=True, samesite="strict", secure=request.url.scheme == "https", path="/")
        return response

    @app.delete("/api/session")
    async def logout(request: Request):
        sessions.pop(hashlib.sha256(request.cookies.get(COOKIE, "").encode()).hexdigest(), None)
        from fastapi.responses import JSONResponse
        response = JSONResponse({"authenticated": False})
        response.delete_cookie(COOKIE)
        return response

    def safe_base_status():
        try:
            return settings.base_status()
        except (OSError, ValueError, TypeError, AttributeError, RecursionError):
            return {"status": "not_ready", "metadata": {}}

    @app.get("/api/runtime-status", dependencies=[Depends(authenticated)])
    async def operational_status():
        return await asyncio.to_thread(runtime_status, safe_base_status())

    @app.get("/api/capabilities", dependencies=[Depends(authenticated)])
    async def capabilities():
        from lab.static_analysis import capabilities as static_capabilities
        from lab.vm import capabilities as vm_capabilities
        static = await asyncio.to_thread(static_capabilities, settings.tools)
        try:
            dynamic = await asyncio.to_thread(vm_capabilities, settings.base_dir)
        except (OSError, ValueError, TypeError, AttributeError, RecursionError):
            dynamic = {"status": "unavailable", "verified": False, "detail": "Metadati della base non leggibili; isolamento non verificato."}
        base = safe_base_status()
        operational = await asyncio.to_thread(runtime_status, base)
        internet = any(profile.get("network") == "internet" for profile in PROFILES)
        return {**operational, "profiles": [{**profile, "status": "ready" if base["status"] == "ready" else "not_ready", "os": "Windows 11 (stessa base per tutti i profili)"} for profile in PROFILES],
                "tools": static, "isolation": dynamic, "base": base, "integrations": external_capabilities(),
                "limits": {"max_upload": settings.max_upload, "max_duration": 600, "sequential_vms": True,
                           "internet": internet,
                           "guest_lan": False, "guest_host": False, "ipv6": False},
                "network_policy": {"mode": "public_ipv4_only" if internet else "offline", "required": True, "confirmed": False,
                                   "detail": "Internet opt-in via gateway confinato; blocco host/LAN/privati, IPv6 e DNS locali verificato prima del campione. La prova effettiva è nel report della singola esecuzione." if internet else "Profili configurati offline; assenza di accesso alla rete e isolamento da verificare prima del campione. La prova effettiva è nel report della singola esecuzione."},
                "kernel": {"status": "configured", "source": "Microsoft kernel ETW/WPR",
                           "detail": "Syscall e stack kernel richiesti; disponibilità, perdita eventi e lacune misurate per ogni esecuzione, senza disattivare protezioni."},
                "sharing": {"public_origin_configured": bool(share_origin(settings)), "detail": "Report ridotti, link HTTPS con scadenza/revocabili. Gateway pubblico separato: nessun accesso a sample o API privata."}}

    def get_job(job_id):
        if not re.fullmatch(r"[0-9a-f]{32}", job_id):
            raise HTTPException(404, "Analisi non trovata")
        job = store.get(job_id)
        if not job:
            raise HTTPException(404, "Analisi non trovata")
        return job

    @app.get("/api/jobs", dependencies=[Depends(authenticated)])
    async def list_jobs(limit: int = 100, offset: int = 0):
        limit = max(1, min(200, limit))
        offset = max(0, offset)
        jobs = store.list(limit, offset)
        return {"jobs": [{key: job.get(key) for key in ("id", "name", "sha256", "status", "created_at", "updated_at", "finished_at", "summary", "options")} for job in jobs]}

    @app.post("/api/jobs", dependencies=[Depends(authenticated)])
    async def submit(file: UploadFile = File(...), profiles: str = Form('["standard"]'), duration: int = Form(60), static_only: bool = Form(False)):
        if not 15 <= duration <= 600:
            raise HTTPException(422, "Durata tra 15 e 600 secondi")
        try:
            selected = json.loads(profiles)
        except ValueError:
            raise HTTPException(422, "Profili: atteso array JSON")
        if not isinstance(selected, list) or not all(isinstance(value, str) and value in PROFILE_MAP for value in selected) or len(selected) > 4 or len(set(selected)) != len(selected):
            raise HTTPException(422, "Profili non validi")
        if not static_only and not selected:
            raise HTTPException(422, "Scegli almeno un profilo")
        if not static_only and settings.base_status()["status"] != "ready":
            raise HTTPException(409, "Base di analisi non ancora pronta: puoi usare solo analisi statica")
        async with upload_lock:
            if store.pending_count() >= settings.max_queue:
                raise HTTPException(429, "Coda piena")
            if shutil.disk_usage(settings.data).free < settings.max_upload + 8 * 1024 * 1024 * 1024:
                raise HTTPException(507, "Spazio insufficiente per una VM usa-e-getta")
            job_id = uuid.uuid4().hex
            raw_name = (file.filename or "sample.bin").replace("\\", "/").rsplit("/", 1)[-1]
            name = re.sub(r"[^\w.() -]", "_", raw_name, flags=re.UNICODE)[:160].strip(" .") or "sample.bin"
            extension = Path(name).suffix.lower()
            if not re.fullmatch(r"\.[a-z0-9]{1,8}", extension):
                extension = ".bin"
            destination = settings.samples / (job_id + extension)
            size = 0
            digest = hashlib.sha256()
            try:
                fd = os.open(destination, os.O_CREAT | os.O_WRONLY | os.O_EXCL, 0o600)
                with os.fdopen(fd, "wb") as stream:
                    while chunk := await file.read(1024 * 1024):
                        size += len(chunk)
                        if size > settings.max_upload:
                            raise HTTPException(413, "Sample troppo grande: massimo 100 MB")
                        digest.update(chunk)
                        stream.write(chunk)
                if not size:
                    raise HTTPException(422, "Il file è vuoto")
                now = utcnow()
                job = {"id": job_id, "name": name, "sha256": digest.hexdigest(), "size": size, "status": "queued", "created_at": now, "updated_at": now,
                       "options": {"profiles": [] if static_only else selected, "duration": duration, "static_only": static_only}, "static": {}, "runs": [] if static_only else [{"profile": value, "profile_name": PROFILE_MAP[value]["name"], "status": "pending", "warnings": []} for value in selected],
                       "artifacts": [], "warnings": [], "summary": {}, "_sample_path": str(destination.resolve()), "cancel_requested": False}
                (settings.jobs / job_id).mkdir(mode=0o700)
                store.put(job)
                worker.submit(job_id)
            except (HTTPException, queue.Full):
                destination.unlink(missing_ok=True)
                raise
            finally:
                await file.close()
        return {"id": job_id, "status": "queued"}

    @app.get("/api/jobs/{job_id}", dependencies=[Depends(authenticated)])
    async def detail(job_id: str):
        from lab.views import detail_view
        result = await asyncio.to_thread(lambda: detail_view(get_job(job_id)))
        for run in result.get("runs", []):
            dynamic = run.get("dynamic")
            if isinstance(dynamic, dict):
                dynamic["privacy_summary"] = privacy_proof_summary(dynamic.get("privacy"), scope="runtime_pretransfer")
        return result

    @app.post("/api/jobs/{job_id}/cancel", dependencies=[Depends(authenticated)])
    async def cancel(job_id: str):
        job = get_job(job_id)
        if job["status"] not in TERMINAL:
            store.update(job_id, cancel_requested=True)
        return {"id": job_id, "cancel_requested": True, "status": job["status"]}

    @app.get("/api/jobs/{job_id}/events", dependencies=[Depends(authenticated)])
    async def events(job_id: str, run: str = "standard", related: bool = True, category: str = "", q: str = "", offset: int = 0, limit: int = 200):
        job = get_job(job_id)
        selected = next((value for value in job.get("runs", []) if value["profile"] == run), None)
        if not selected:
            raise HTTPException(404, "Profilo non trovato")
        indexed = await asyncio.to_thread(store.events_page, job_id, run, related, category, q, offset, limit)
        if indexed is not None:
            return indexed
        values = selected.get("dynamic", {}).get("events", [])
        if related:
            values = [value for value in values if value.get("related")]
        if category:
            values = [value for value in values if value.get("category") == category]
        if q:
            needle = q[:200].casefold()
            values = [value for value in values if needle in json.dumps(value, ensure_ascii=False).casefold()]
        offset = max(0, offset)
        limit = max(1, min(500, limit))
        return {"items": values[offset:offset + limit], "total": len(values), "offset": offset, "limit": limit}

    @app.get("/api/jobs/{job_id}/artifacts/{artifact_id}", dependencies=[Depends(authenticated)])
    async def artifact(job_id: str, artifact_id: str):
        job = get_job(job_id)
        value = next((value for value in job.get("artifacts", []) if value["id"] == artifact_id), None)
        if not value:
            raise HTTPException(404, "Artefatto non trovato")
        path = Path(value["_path"])
        root = (settings.jobs / job_id).resolve()
        if path.is_symlink() or not path.is_file() or not path.resolve().is_relative_to(root):
            raise HTTPException(404, "Artefatto non disponibile")
        return FileResponse(path, filename=value["name"], media_type="application/octet-stream")

    @app.get("/api/jobs/{job_id}/report.pdf", dependencies=[Depends(authenticated)])
    async def pdf(job_id: str):
        job = get_job(job_id)
        if job["status"] not in TERMINAL:
            raise HTTPException(409, "Attendi il completamento per il PDF")
        destination = settings.jobs / job_id / "report.pdf"
        def generate():
            with pdf_lock:
                render_pdf(public_job(job), destination)
        await asyncio.to_thread(generate)
        return FileResponse(destination, filename="blacksite-" + job["sha256"][:12] + ".pdf", media_type="application/pdf")

    @app.post("/api/jobs/{job_id}/share", dependencies=[Depends(authenticated)])
    async def share(job_id: str, payload: ShareRequest):
        job = get_job(job_id)
        if job["status"] not in TERMINAL:
            raise HTTPException(409, "Condividi solo analisi terminate")
        token, expires = store.share(job_id, payload.hours)
        origin = share_origin(settings)
        return {"url": origin + "/s/" + token, "expires_at": expires, "public": bool(origin), "temporary": not bool(settings.public_origin) and bool(origin)}

    @app.delete("/api/jobs/{job_id}/share", dependencies=[Depends(authenticated)])
    async def revoke(job_id: str):
        get_job(job_id)
        store.revoke(job_id)
        return {"revoked": True}

    @app.get("/api/shared/{token}")
    async def shared(token: str):
        job = store.shared_job(token)
        if not job:
            raise HTTPException(404, "Link scaduto, revocato o inesistente")
        return redacted_share(job)

    @app.get("/api/openapi.json", dependencies=[Depends(authenticated)])
    async def schema():
        return app.openapi()

    app.mount("/static", StaticFiles(directory=settings.root / "static", check_dir=False), name="static")

    @app.get("/s/{token}")
    async def share_page(token: str):
        if not re.fullmatch(r"[A-Za-z0-9_-]{30,128}", token):
            raise HTTPException(404, "Link non valido")
        return FileResponse(settings.root / "static/index.html")

    @app.get("/")
    async def index():
        return FileResponse(settings.root / "static/index.html")

    return app

app = create_app()
