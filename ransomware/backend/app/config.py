import os
from pydantic_settings import BaseSettings

class Settings(BaseSettings):
    DATABASE_URL: str = "sqlite:///./ransomware_defense.db"
    JWT_SECRET: str = "change-me-jwt-secret"
    ENVIRONMENT: str = "development"
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 1440
    REDIS_HOST: str = "localhost"
    REDIS_PORT: int = 6379
    WEBHOOK_URL: str = ""
    AGENT_SHARED_SECRET: str = "change-me-agent-secret"

    class Config:
        env_file = ".env"
        extra = "ignore"

settings = Settings()
