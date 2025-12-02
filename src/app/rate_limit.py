import time
from collections import defaultdict, deque
from typing import Deque, Dict

from fastapi import HTTPException, Request, status


class RateLimiter:
    def __init__(self, calls: int, period_seconds: int) -> None:
        self.calls = calls
        self.period_seconds = period_seconds
        self._hits: Dict[str, Deque[float]] = defaultdict(deque)

    def _key_from_request(self, request: Request) -> str:
        client_host = request.client.host if request.client else "unknown"
        return client_host

    async def __call__(self, request: Request) -> None:
        key = self._key_from_request(request)
        now = time.time()
        q = self._hits[key]

        # limpiar timestamps fuera de ventana
        while q and now - q[0] > self.period_seconds:
            q.popleft()

        if len(q) >= self.calls:
            raise HTTPException(
                status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                detail="Too many requests, slow down.",
            )

        q.append(now)


login_rate_limiter = RateLimiter(calls=5, period_seconds=60)
