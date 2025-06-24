# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

NetzZwergenWacht is an intelligent, automated system for analyzing and monitoring website quality using LLM-powered software agents called "Dwarfs". The system performs automated E2E interactions, surface-level quality analysis, and generates intelligent reports with LLM insights.

## Technology Stack

- **Language**: Python (requires >=3.12)
- **Project Management**: uv
- **Browser Automation**: Playwright (planned)
- **Testing**: pytest
- **Linting**: ruff

## Development Commands

### Project Setup
```bash
# Install dependencies
uv sync

# Install development dependencies
uv sync --dev

# Add new dependencies
uv add <package>

# Add development dependencies
uv add --dev <package>

# Install pre-commit hooks
uv run pre-commit install
```

### Running the Application
```bash
# Using installed package scripts
uv run netzzwergenwacht --help
uv run nzw --help  # Short alias

# Direct module execution
uv run python -m netzzwergenwacht.cli.main --help

# Legacy compatibility (main.py)
uv run python main.py  # Shows deprecation warning
```

### Basic Usage Examples
```bash
# Check a website
uv run netzzwergenwacht check https://example.com

# Check with verbose output
uv run nzw check https://example.com --verbose

# Save results to file
uv run nzw check https://example.com --output results.txt

# Show version
uv run nzw version
```

### Testing and Quality
```bash
# Run tests
uv run pytest

# Run tests with coverage
uv run pytest --cov=src

# Run linter
uv run ruff check

# Fix linting issues automatically
uv run ruff check --fix

# Format code
uv run ruff format

# Type checking
uv run mypy src/

# Run all quality checks
uv run ruff check && uv run ruff format && uv run mypy src/ && uv run pytest
```

## Architecture

Currently in Phase 0 (Foundation & Setup) - the project contains a minimal structure:

- `main.py` - Entry point with basic "Hello World" functionality
- `pyproject.toml` - Project configuration and dependencies
- Core "Browser Dwarf" functionality planned for Phase 1

### Planned Architecture (from README.md)

The system will be built around modular "Dwarf" agents:

1. **Browser Dwarf** - Core browser automation using Playwright
2. **Analysis Modules** - Surface-level quality checks (broken links, console errors, SEO)
3. **LLM Integration** - Intelligence layer for issue classification and reporting
4. **Reporting System** - Structured output with alerts and notifications
5. **Configuration & Scheduling** - User-configurable monitoring setup

## Development Phases

The project follows a phased approach outlined in README.md:
- **Phase 0**: Foundation & Setup (current)
- **Phase 1**: Core Browser Interaction
- **Phase 2**: Basic Surface Checks
- **Phase 3**: LLM Integration
- **Phase 4**: Enhanced Reporting & Actions
- **Phase 5**: Configuration, Scheduling & Usability

## Key Design Principles

- LLM-powered intelligent analysis and classification
- Modular "Dwarf" agent architecture
- Configurable and scheduled monitoring
- Clear reporting with actionable insights
- Browser automation for realistic user journey simulation
