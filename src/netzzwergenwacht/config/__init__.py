"""Configuration management."""
"""Centralized configuration management for NetzZwergenWacht."""
from enum import Enum
from pathlib import Path
from typing import Literal, Annotated

from pydantic import Field, field_validator, DirectoryPath
from pydantic_settings import BaseSettings, SettingsConfigDict

class LogFormat(str, Enum):
    """Supported log formats."""
    RICH = "rich"
    JSON = "json"
    PLAIN = "plain"

class AppConfig(BaseSettings):
    """Main application configuration with environment variable support.
    
    Configuration can be set via:
    - Environment variables (prefixed with NZW_)
    - .env file
    - Programmatic override
    """

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        env_prefix="NZW_",
        extra="ignore",
        case_sensitive=False
    )

    # Logging Configuration
    log_level: Annotated[
        Literal["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"],
        Field("INFO", description="Logging verbosity level")
    ] = "INFO"
    
    log_format: Annotated[
        LogFormat,
        Field(LogFormat.RICH, description="Log output format")
    ] = LogFormat.RICH

    log_file: Annotated[
        Path | None,
        Field(None, description="Path to log file (optional)")
    ] = None

    log_dir: Annotated[
        DirectoryPath,
        Field(Path("logs"), description="Directory for log files")
    ] = Path("logs")

    # Network Configuration
    request_timeout: Annotated[
        float,
        Field(30.0, gt=0, description="HTTP request timeout in seconds")
    ] = 30.0

    max_redirects: Annotated[
        int,
        Field(5, ge=0, description="Maximum HTTP redirects to follow")
    ] = 5

    user_agent: Annotated[
        str,
        Field("NetzZwergenWacht/0.1.0", description="HTTP User-Agent header")
    ] = "NetzZwergenWacht/0.1.0"

    # Security Configuration
    allow_insecure: Annotated[
        bool,
        Field(False, description="Allow insecure HTTPS connections")
    ] = False

    scan_ports: Annotated[
        bool,
        Field(True, description="Enable port scanning")
    ] = True

    # Performance Configuration
    max_workers: Annotated[
        int,
        Field(10, ge=1, le=100, description="Max concurrent workers")
    ] = 10

    # Dwarf Configuration
    enable_llm: Annotated[
        bool,
        Field(False, description="Enable LLM-powered analysis")
    ] = False

    @field_validator("log_dir")
    def ensure_log_dir_exists(cls, v: Path) -> Path:
        """Ensure log directory exists."""
        v.mkdir(exist_ok=True, parents=True)
        return v

    @field_validator("log_file")
    def resolve_log_path(cls, v: Path | None, values) -> Path | None:
        """Resolve log file path relative to log_dir if not absolute."""
        if v is None:
            return None
        if not v.is_absolute() and "log_dir" in values:
            return values["log_dir"] / v
        return v

def get_config(**overrides) -> AppConfig:
    """Get the application configuration with optional overrides.
    
    Args:
        **overrides: Configuration values to override
    
    Returns:
        AppConfig: Configured application settings
    """
    return AppConfig(**overrides)

# Global configuration instance
config = get_config()
