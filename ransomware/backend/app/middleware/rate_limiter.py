import os
from fastapi import Request, status
from fastapi.responses import JSONResponse
from starlette.middleware.base import BaseHTTPMiddleware
from app.redis_client import redis_client

class RateLimitingMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        path = request.url.path
        # Exclude API documentation paths or bypass in tests
        if os.getenv("TESTING") == "True" or path.startswith("/docs") or path.startswith("/openapi.json") or path.startswith("/redoc"):
            return await call_next(request)

        client_ip = request.client.host
        key = f"rate_limit:{client_ip}"

        # Limit: 60 requests per minute
        count = redis_client.increment_rate_limit(key, window_seconds=60)
        if count > 60:
            return JSONResponse(
                status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                content={"detail": "Too many requests. Rate limit exceeded (60 req/min)."}
            )

        return await call_next(request)
