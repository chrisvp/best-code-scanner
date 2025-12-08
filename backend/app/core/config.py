from pydantic_settings import BaseSettings
from typing import Optional

class Settings(BaseSettings):
    PROJECT_NAME: str = "Davy Code Scanner"
    PROJECT_VERSION: str = "0.1.0"
    API_V1_STR: str = "/api/v1"
    
    # Database - use Linux filesystem to avoid WSL2 I/O issues
    DATABASE_URL: str = "sqlite:////tmp/scans.db"
    DB_PASSWORD: str = "changeme_in_prod" # SQLCipher key (Unused in dev)
    
    # Security
    SECRET_KEY: str = "supersecretkey"
    SESSION_TIMEOUT_HOURS: int = 24
    SESSION_REMEMBER_DAYS: int = 30
    MIN_PASSWORD_LENGTH: int = 8
    
    # LLM Configuration
    LLM_BASE_URL: str = "https://192.168.33.158:5000/v1"
    LLM_API_KEY: str = "testkeyforchrisvp"
    LLM_VERIFY_SSL: bool = False
    LLM_MODEL: str = "llama3.3-70b-instruct"
    LLM_VERIFICATION_MODELS: list[str] = ["mistral-small", "gemma-3-27b-it"]
    
    # Concurrency
    MAX_CONCURRENT_REQUESTS: int = 5
    MAX_CONCURRENT_ON_DEMAND_SCANS: int = 3  # Max on-demand (manual) scans running simultaneously
    MAX_CONCURRENT_WATCHER_SCANS: int = 2     # Max watcher-triggered scans running simultaneously

    # Joern Configuration
    JOERN_DOCKER_IMAGE: str = "ghcr.io/joernio/joern:nightly"
    JOERN_TIMEOUT: int = 600  # Seconds to wait for Joern operations

    # Scanner URL (for links in MR comments)
    SCANNER_URL_PREFIX: str = "http://localhost:8000"

    class Config:
        env_file = ".env"
        case_sensitive = True

settings = Settings()
