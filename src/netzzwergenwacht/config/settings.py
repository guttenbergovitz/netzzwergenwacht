"""Configuration management using Pydantic."""

from pathlib import Path

from pydantic import Field
from pydantic_settings import BaseSettings


class Settings(BaseSettings):
    """Application settings."""

    # Browser settings
    browser_headless: bool = Field(True, description="Run browser in headless mode")
    browser_timeout: int = Field(30000, description="Browser timeout in milliseconds")
    browser_user_agent: str = Field(
        "NZW Browser Dwarf v0.1.0", description="User agent string"
    )

    # LLM settings (for future use)
    llm_provider: str = Field("openai", description="LLM provider")
    llm_model: str = Field("gpt-4", description="LLM model to use")
    llm_api_key: str | None = Field(None, description="LLM API key")
    llm_temperature: float = Field(0.3, description="LLM temperature")

    # Monitoring settings
    default_checks: list[str] = Field(
        ["links", "console", "seo"], description="Default checks to perform"
    )
    max_concurrent_checks: int = Field(5, description="Maximum concurrent checks")

    # Output settings
    output_format: str = Field("console", description="Default output format")
    log_level: str = Field("INFO", description="Logging level")
    log_file: Path | None = Field(None, description="Log file path")

    # Rate limiting
    request_delay: float = Field(1.0, description="Delay between requests in seconds")
    max_retries: int = Field(3, description="Maximum number of retries")

    model_config = {
        "env_file": ".env",
        "env_prefix": "NZW_",
        "case_sensitive": False,
    }


def get_settings() -> Settings:
    """Get application settings."""
    return Settings()
