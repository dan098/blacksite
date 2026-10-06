from starlette.exceptions import HTTPException
from starlette.responses import JSONResponse


class BodyLimitMiddleware:
    """Bound even chunked multipart uploads before they can fill the spool disk."""
    def __init__(self, app, max_upload):
        self.app = app
        self.max_upload = max_upload

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http" or scope["method"] not in {"POST", "PUT", "PATCH", "DELETE"}:
            await self.app(scope, receive, send)
            return
        limit = self.max_upload + 1024 * 1024 if scope["path"] == "/api/jobs" else 64 * 1024
        headers = dict(scope.get("headers", []))
        raw_length = headers.get(b"content-length")
        if raw_length:
            try:
                size = int(raw_length)
                if size < 0:
                    raise ValueError()
            except ValueError:
                await JSONResponse({"detail": "Content-Length non valido"}, status_code=400)(scope, receive, send)
                return
            if size > limit:
                await JSONResponse({"detail": "Corpo HTTP oltre il limite"}, status_code=413)(scope, receive, send)
                return
        received = 0

        async def limited_receive():
            nonlocal received
            message = await receive()
            if message["type"] == "http.request":
                received += len(message.get("body", b""))
                if received > limit:
                    raise HTTPException(413, "Corpo HTTP oltre il limite")
            return message

        await self.app(scope, limited_receive, send)
