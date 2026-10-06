"""Only the reduced shared view is reachable from the public tunnel."""
from contextlib import asynccontextmanager
from pathlib import Path
import re

import httpx
from fastapi import FastAPI, HTTPException
from fastapi.responses import FileResponse, JSONResponse
from starlette.middleware.trustedhost import TrustedHostMiddleware

TOKEN = re.compile(r'[A-Za-z0-9_-]{30,128}')
STATIC = Path(__file__).resolve().parents[1] / 'static'


def create_public_app(transport=None):
    @asynccontextmanager
    async def lifespan(app):
        async with httpx.AsyncClient(base_url='http://127.0.0.1:8765', timeout=10,
                                     trust_env=False, follow_redirects=False, transport=transport,
                                     limits=httpx.Limits(max_connections=8, max_keepalive_connections=4)) as client:
            app.state.client = client
            yield

    app = FastAPI(title='Sandbox Lab shared reports', docs_url=None, redoc_url=None,
                  openapi_url=None, lifespan=lifespan)
    app.add_middleware(TrustedHostMiddleware, allowed_hosts=['127.0.0.1','localhost','testserver','*.trycloudflare.com'])

    @app.middleware('http')
    async def hardening(request, call_next):
        response = await call_next(request)
        response.headers.update({
            'Content-Security-Policy': "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; connect-src 'self'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'; form-action 'none'",
            'X-Content-Type-Options': 'nosniff', 'Referrer-Policy': 'no-referrer',
            'X-Frame-Options': 'DENY', 'X-Robots-Tag': 'noindex, nofollow', 'Cache-Control': 'no-store',
        })
        return response

    @app.get('/s/{token}')
    async def page(token: str):
        if not TOKEN.fullmatch(token):
            raise HTTPException(404)
        return FileResponse(STATIC / 'index.html')

    @app.get('/static/{name}')
    async def asset(name: str):
        if name not in {'app.js', 'style.css'}:
            raise HTTPException(404)
        return FileResponse(STATIC / name)

    @app.get('/api/shared/{token}')
    async def shared(token: str):
        if not TOKEN.fullmatch(token):
            raise HTTPException(404)
        try:
            async with app.state.client.stream('GET', '/api/shared/' + token) as response:
                if response.status_code != 200:
                    raise HTTPException(404 if response.status_code in (403,404,410) else 503, 'Link non disponibile')
                body = bytearray()
                async for chunk in response.aiter_bytes():
                    body.extend(chunk)
                    if len(body) > 256 * 1024:
                        raise HTTPException(503, 'Risposta oltre limite')
            import json
            return JSONResponse(json.loads(body))
        except (httpx.HTTPError, ValueError):
            raise HTTPException(503, 'Laboratorio temporaneamente non raggiungibile')

    return app


app = create_public_app()
