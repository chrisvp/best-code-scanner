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
    
    # LLM Configuration
    LLM_BASE_URL: str = "https://192.168.33.158:5000/v1"
    LLM_API_KEY: str = "testkeyforchrisvp"
    LLM_VERIFY_SSL: bool = False
    LLM_MODEL: str = "llama3.3-70b-instruct"
    LLM_VERIFICATION_MODELS: list[str] = ["mistral-small", "gemma-3-27b-it"]
    
    # Concurrency
    MAX_CONCURRENT_REQUESTS: int = 5
    
    class Config:
        env_file = ".env"
        case_sensitive = True

settings = Settings()
