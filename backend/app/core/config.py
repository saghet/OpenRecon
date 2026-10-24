from pydantic_settings import BaseSettings
from typing import Optional


class Settings(BaseSettings):
    PROJECT_NAME: str = "OpenRecon"
    VERSION: str = "0.1.0"
    API_V1_STR: str = "/api/v1"
    SECRET_KEY: str = "openrecon_development_secret_key"
    
    # Database
    DATABASE_URL: str = "sqlite:///./openrecon.db"
    
    # Redis
    REDIS_URL: Optional[str] = None
    
    # Operational & Safety Rules
    SAFE_MODE: bool = True
    MAX_CONCURRENT_TASKS: int = 5
    RATE_LIMIT_RPS: int = 15
    ENABLE_EXTERNAL_BINARIES: bool = True
    
    class Config:
        case_sensitive = True
        env_file = ".env"


settings = Settings()
