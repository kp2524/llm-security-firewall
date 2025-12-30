"""Configuration management for the LLM Guardrail Proxy."""
import os
from pydantic_settings import BaseSettings
from typing import Optional


class Settings(BaseSettings):
    """Application settings loaded from environment variables."""
    
    # Google Gemini API
    gemini_api_key: str
    
    # Security Thresholds
    similarity_threshold: float = 0.85
    
    # File Paths
    log_file_path: str = "security_logs.txt"
    jailbreak_db_path: str = "jailbreak_patterns.json"
    
    class Config:
        env_file = ".env"
        env_file_encoding = "utf-8"
        case_sensitive = False


# Global settings instance
settings = Settings()

