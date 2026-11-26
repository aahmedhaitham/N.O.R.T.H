"""Protect a loopback-only NORTH session against cross-origin browser requests."""

import hmac
import re
import secrets

from fastapi.responses import JSONResponse
from starlette.datastructures import Headers
from starlette.requests import HTTPConnection


COOKIE = "north_local_session"
LOOPBACK_HOST = re.compile(r"(?:localhost|127\.0\.0\.1|\[::1\])(?::[0-9]{1,5})?", re.IGNORECASE)
SESSION_VALUE = re.compile(r"[A-Za-z0-9_-]{43}\.[0-9a-f]{64}")


class LocalAccess:
    def __init__(self, app):
        self.app = app
        self.session_key = secrets.token_bytes(32)

    def signature(self, nonce):
        return hmac.digest(self.session_key, nonce.encode("ascii"), "sha256").hex()

    def new_session(self):
        nonce = secrets.token_urlsafe(32)
        return nonce + "." + self.signature(nonce)

    def valid_session(self, supplied):
        if not SESSION_VALUE.fullmatch(supplied):
            return False
        nonce, signature = supplied.split(".")
        return secrets.compare_digest(self.signature(nonce), signature)

    async def __call__(self, scope, receive, send):
        if scope["type"] not in ("http", "websocket"):
            await self.app(scope, receive, send)
            return
        headers = Headers(scope=scope)
        host = headers.get("host", "")
        origin = headers.get("origin")
        site = headers.get("sec-fetch-site")
        path = scope["path"]
        status = 0
        if len(headers.getlist("host")) != 1 or not LOOPBACK_HOST.fullmatch(host):
            status = 400
        elif (origin is not None and origin not in (f"http://{host}", f"https://{host}")) or site in ("cross-site", "same-site"):
            status = 403
        elif scope["type"] == "http" and path == "/api/local-session":
            if scope["method"] != "POST" or headers.get("x-north-local-session") != "start":
                status = 403
            else:
                response = JSONResponse({"status": "ok"}, headers={"Cache-Control": "no-store"})
                response.set_cookie(COOKIE, self.new_session(), httponly=True, samesite="strict",
                                    secure=scope.get("scheme") == "https", path="/api/")
                await response(scope, receive, send)
                return
        elif path.startswith("/api/") and path != "/api/health":
            supplied = HTTPConnection(scope).cookies.get(COOKIE, "")
            if not self.valid_session(supplied):
                status = 401
        if not status:
            await self.app(scope, receive, send)
        elif scope["type"] == "websocket":
            await send({"type": "websocket.close", "code": 1008})
        else:
            await JSONResponse({"detail": "Local NORTH request rejected"}, status_code=status)(scope, receive, send)
