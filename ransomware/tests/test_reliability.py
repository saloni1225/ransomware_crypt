from unittest.mock import patch, MagicMock
import os
import pytest
import redis

from app.database import check_and_create_database
from app.redis_client import RedisClient

def test_db_fallback_to_sqlite():
    with patch.dict(os.environ, {"TESTING": "False"}):
        with patch("psycopg2.connect", side_effect=Exception("Database down")):
            url = check_and_create_database("postgresql://user:pass@localhost:5432/db")
            assert url == "sqlite:///./ransomware_defense.db"

def test_redis_connection_error_graceful_fallback():
    mock_redis = MagicMock()
    mock_redis.setex.side_effect = redis.ConnectionError("Connection lost")
    mock_redis.exists.side_effect = redis.ConnectionError("Connection lost")
    
    mock_pipe = MagicMock()
    mock_pipe.execute.side_effect = redis.ConnectionError("Connection lost")
    mock_redis.pipeline.return_value = mock_pipe

    client = RedisClient()
    client.client = mock_redis

    # Test token blacklisting fails gracefully
    client.blacklist_token("test_token", 3600)
    
    # Test token blacklist check returns False
    assert client.is_token_blacklisted("test_token") is False
    
    # Test rate limit returns 1 (bypass/fallback value)
    assert client.increment_rate_limit("user_key", 60) == 1
