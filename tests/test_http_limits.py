import asyncio
from lab.http_limits import BodyLimitMiddleware


def test_known_length_refused_before_receive():
    called = []
    sent = []
    async def inner(scope, receive, send):
        called.append(True)
    async def receive():
        raise AssertionError("Body should not be consumed")
    async def send(message):
        sent.append(message)
    middleware = BodyLimitMiddleware(inner, max_upload=10)
    asyncio.run(middleware({"type": "http", "method": "POST", "path": "/api/session", "headers": [(b"content-length", b"100000")]}, receive, send))
    assert not called
    assert sent[0]["status"] == 413


def test_chunked_size_is_bounded():
    from starlette.exceptions import HTTPException
    caught = []
    async def inner(scope, receive, send):
        try:
            await receive()
            await receive()
        except HTTPException as exc:
            caught.append(exc.status_code)
    async def receive():
        return {"type": "http.request", "body": b"x" * 40000, "more_body": True}
    async def send(message):
        pass
    middleware = BodyLimitMiddleware(inner, max_upload=10)
    asyncio.run(middleware({"type": "http", "method": "POST", "path": "/api/session", "headers": []}, receive, send))
    assert caught == [413]
