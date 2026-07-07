import redis
from app.config import settings

class RedisClient:
    def __init__(self):
        try:
            self.client = redis.Redis(
                host=settings.REDIS_HOST,
                port=settings.REDIS_PORT,
                decode_responses=True,
                socket_connect_timeout=2
            )
        except Exception as e:
            print(f"Redis connection initialization error: {e}")
            self.client = None

    def blacklist_token(self, token: str, expires_in_seconds: int):
        if not self.client:
            return
        try:
            self.client.setex(f"blacklist:{token}", expires_in_seconds, "true")
        except Exception as e:
            print(f"Redis blacklist_token error: {e}")

    def is_token_blacklisted(self, token: str) -> bool:
        if not self.client:
            return False
        try:
            return self.client.exists(f"blacklist:{token}") > 0
        except Exception as e:
            print(f"Redis is_token_blacklisted error: {e}")
            return False

    def increment_rate_limit(self, key: str, window_seconds: int = 60) -> int:
        if not self.client:
            return 1  # Bypass rate limiting if Redis is unavailable
        try:
            pipe = self.client.pipeline()
            pipe.incr(key)
            pipe.expire(key, window_seconds, nx=True)
            res = pipe.execute()
            return res[0]
        except Exception as e:
            print(f"Redis increment_rate_limit error: {e}")
            return 1

redis_client = RedisClient()
