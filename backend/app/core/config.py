from pydantic_settings import BaseSettings
from typing import List, Optional


class Settings(BaseSettings):
    PROJECT_NAME: str = "OpenRecon"
    VERSION: str = "3.0.0-alpha"
    API_V1_STR: str = "/api/v1"
    SECRET_KEY: str = "openrecon_development_secret_key"
    OPENRECON_MASTER_KEY: Optional[str] = None
    OPENRECON_API_TOKEN: Optional[str] = None

    # CORS
    CORS_ALLOWED_ORIGINS: List[str] = [
        "http://localhost",
        "http://127.0.0.1",
        "http://localhost:80",
        "http://localhost:8000",
        "http://127.0.0.1:8000",
    ]

    # TLS / CA Configuration
    CUSTOM_CA_BUNDLE: Optional[str] = None

    # Database
    DATABASE_URL: str = "sqlite:///./openrecon.db"

    # Redis
    REDIS_URL: Optional[str] = None

    # Operational & Safety Rules
    SAFE_MODE: bool = True
    MAX_CONCURRENT_TASKS: int = 5
    RATE_LIMIT_RPS: int = 15
    ENABLE_EXTERNAL_BINARIES: bool = True

    # Defensive Tor Sandbox Configuration
    TOR_PROXY_URL: str = "socks5h://127.0.0.1:9050"
    TOR_REQUEST_TIMEOUT: float = 15.0
    TOR_MAX_REDIRECTS: int = 3
    TOR_MAX_CONTENT_BYTES: int = 2 * 1024 * 1024  # 2MB max payload
    TOR_VERIFY_SSL: bool = True  # Strict TLS verification enabled by default

    # External CTI Integrations
    OPENCTI_URL: Optional[str] = None
    OPENCTI_TOKEN: Optional[str] = None
    MISP_URL: Optional[str] = None
    MISP_KEY: Optional[str] = None

    # DeepSeek Analytical AI Config
    DEEPSEEK_API_KEY: Optional[str] = None
    DEEPSEEK_BASE_URL: str = "https://api.deepseek.com/v1"
    DEEPSEEK_MODEL: str = "deepseek-chat"

    class Config:
        case_sensitive = True
        env_file = ".env"
        extra = "ignore"


settings = Settings()
