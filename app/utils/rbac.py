# app/utils/rbac.py
from typing import Callable, Iterable, Optional
from fastapi import Depends, HTTPException, status, Request
from fastapi.security import OAuth2PasswordBearer
from app.utils import security

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/auth/login")


def get_payload_from_token(token: str = Depends(oauth2_scheme)) -> dict:
    """
    Decode JWT token and return payload dict. Raises 401 on failure.
    """
    try:
        payload = security.decode_token(token)
        return payload
    except Exception as e:
        # decode_token already raises HTTPException on failure, just re-raise
        raise


def require_roles(*allowed_roles: Iterable[str]) -> Callable:
    """
    Dependency factory for role checks.

    Usage:
        @app.get("/admin/secret")
        def admin_secret(payload=Depends(require_roles("admin"))):
            ...
    Returns the token payload (so handler can use 'sub'/'username'/'role').
    """
    allowed_set = set(allowed_roles)

    def _dependency(payload: dict = Depends(get_payload_from_token)):
        role = payload.get("role")
        if role is None or role not in allowed_set:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Forbidden: insufficient role",
            )
        return payload

    return _dependency


# -------------------------
# Optional: middleware for prefix-based RBAC
# -------------------------
def admin_prefix_middleware_factory(required_roles: Optional[Iterable[str]] = ("admin",)):
    """
    Returns ASGI middleware that enforces role(s) for all requests whose path starts with "/admin".
    Install with:
        app.add_middleware(SomeMiddlewareWrapper)  # see example below
    NOTE: FastAPI's add_middleware expects a class; this helper returns a class.
    """

    class _AdminPrefixMiddleware:
        def __init__(self, app):
            self.app = app
            self._req_roles = set(required_roles)

        async def __call__(self, scope, receive, send):
            # only enforce for HTTP requests
            if scope["type"] != "http":
                await self.app(scope, receive, send)
                return

            path = scope.get("path", "")
            if not path.startswith("/admin"):
                await self.app(scope, receive, send)
                return

            # attempt to get Authorization header
            headers = dict((k.decode("latin-1"), v.decode("latin-1")) for k, v in scope.get("headers", []))
            auth = headers.get("authorization") or headers.get("Authorization")
            if not auth or not auth.lower().startswith("bearer "):
                # return 401 response
                from starlette.responses import JSONResponse
                await JSONResponse({"detail": "Not authenticated"}, status_code=401)(scope, receive, send)
                return

            token = auth.split(None, 1)[1]
            try:
                payload = security.decode_token(token)
                role = payload.get("role")
                if role not in self._req_roles:
                    from starlette.responses import JSONResponse
                    await JSONResponse({"detail": "Forbidden"}, status_code=403)(scope, receive, send)
                    return
            except Exception:
                from starlette.responses import JSONResponse
                await JSONResponse({"detail": "Invalid or expired token"}, status_code=401)(scope, receive, send)
                return

            # all good
            await self.app(scope, receive, send)

    return _AdminPrefixMiddleware