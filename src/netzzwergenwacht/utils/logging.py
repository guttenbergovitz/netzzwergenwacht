"""Structured logging with Dwarf context."""

import logging
import sys
from pathlib import Path

import structlog
from rich.logging import RichHandler


def setup_structured_logging(
    level: str = "INFO", log_file: Path | None = None, enable_json: bool = False
) -> None:
    """Configure structured logging with optional JSON output."""

    processors = [
        structlog.contextvars.merge_contextvars,
        structlog.processors.add_log_level,
        structlog.processors.StackInfoRenderer(),
        structlog.dev.set_exc_info,
        structlog.processors.TimeStamper(fmt="iso"),
    ]

    if enable_json:
        processors.append(structlog.processors.JSONRenderer())
    else:
        processors.append(structlog.dev.ConsoleRenderer())

    structlog.configure(
        processors=processors,
        wrapper_class=structlog.BoundLogger,
        context_class=dict,
        logger_factory=structlog.PrintLoggerFactory(),
        cache_logger_on_first_use=True,
    )

    # Configure standard logging
    logging.basicConfig(
        level=level.upper(),
        format="%(message)s",
        handlers=[RichHandler()] if not enable_json else [],
    )


def setup_logging(
    level: str = "INFO",
    log_file: Path | None = None,
    rich_console: bool = True,
    json_format: bool = False,
) -> logging.Logger:
    """Set up structured logging for the application.

    Args:
        level: Logging level (DEBUG, INFO, WARNING, ERROR, CRITICAL)
        log_file: Optional path to log file
        rich_console: Use rich console handler for colored output
        json_format: Enable JSON formatted logs

    Returns:
        Configured logger instance
    """
    structlog.configure(
        processors=[
            structlog.contextvars.merge_contextvars,
            structlog.processors.add_log_level,
            structlog.processors.StackInfoRenderer(),
            structlog.processors.TimeStamper(fmt="iso"),
            structlog.processors.JSONRenderer()
            if json_format
            else structlog.dev.ConsoleRenderer(),
        ],
        wrapper_class=structlog.BoundLogger,
        context_class=dict,
        logger_factory=structlog.PrintLoggerFactory(),
        cache_logger_on_first_use=True,
    )
    # Create logger
    logger = logging.getLogger("netzzwergenwacht")
    logger.setLevel(getattr(logging, level.upper()))

    # Clear existing handlers
    logger.handlers.clear()

    # Set up formatters
    file_formatter = logging.Formatter(
        "%(asctime)s - %(name)s - %(levelname)s - %(message)s"
    )

    # Console handler
    if rich_console:
        console_handler: logging.Handler = RichHandler(
            rich_tracebacks=True, show_time=False, show_path=False
        )
        console_handler.setFormatter(logging.Formatter("%(message)s"))
    else:
        console_handler = logging.StreamHandler(sys.stdout)
        console_handler.setFormatter(file_formatter)

    logger.addHandler(console_handler)

    # File handler
    if log_file:
        log_file.parent.mkdir(parents=True, exist_ok=True)
        file_handler = logging.FileHandler(log_file)
        file_handler.setFormatter(file_formatter)
        logger.addHandler(file_handler)

    return logger


def get_logger(name: str = "netzzwergenwacht") -> logging.Logger:
    """Get a logger instance.

    Args:
        name: Logger name

    Returns:
        Logger instance
    """
    return logging.getLogger(name)
