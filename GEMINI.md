# GEMINI.md

This file provides guidance to Gemini when working with the `netzzwergenwacht` codebase.

## Project Overview

NetzZwergenWacht is an intelligent, automated system for analyzing and monitoring website quality. It employs "Zwerge" (German-named dwarfs) – intelligent software agents – to perform comprehensive checks, identify issues, and provide actionable insights powered by advanced LLM integration. The project has successfully completed **Phase 3**, which includes full LLM integration.

## Technology Stack

-   **Language**: Python (requires >=3.12)
-   **Package Management**: `uv`
-   **CLI Framework**: `Typer` with `Rich` console
-   **Browser Automation**: `Playwright`
-   **HTTP Client**: `httpx`
-   **HTML Parsing**: `BeautifulSoup`, `lxml`
-   **Security Scanning**: `nmap` (system dependency), `python-nmap`, `safety`
-   **LLM Integration**: `OpenAI API` (requires `OPENAI_API_KEY` environment variable), `crewai`, `langchain`, `langchain-openai`
-   **Testing**: `pytest` (with `pytest-asyncio`, `pytest-cov`)
-   **Code Quality**: `ruff` (linting & formatting), `mypy` (type checking)
-   **Configuration**: `Pydantic` with `pydantic-settings`
-   **Reporting**: `reportlab`, `weasyprint`, `jinja2` (development dependencies)

## Development Commands

### Project Setup

```bash
# Install dependencies
uv sync

# Install development dependencies
uv sync --dev

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
```

### Basic Usage Examples

```bash
# Quick check a website
uv run nzw check https://example.com

# Comprehensive analysis with LLM integration
uv run nzw analyze https://example.com --llm

# Check with verbose output
uv run nzw check https://example.com --verbose

# Save results to file
uv run nzw check https://example.com --output results.json --format json

# Show version
uv run nzw version
```

### LLM-Powered Analysis

To utilize LLM features, set your OpenAI API key:

```bash
export OPENAI_API_KEY="your-api-key-here"
```

Then run:

```bash
uv run nzw analyze https://example.com --llm
```

This provides:
-   Specific technical fixes with exact code locations
-   Copy-paste ready solutions and configuration changes
-   Prioritized implementation roadmaps
-   Business impact assessments
-   Real-time cost tracking and token usage

### Testing and Quality

```bash
# Run all tests
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

The project features a modular architecture with "Dwarf" agents performing specific analyses.

### Core Components

-   **Dwarf Agents**: Modular analysis components, each focusing on a specific aspect of website quality (e.g., `WebBrowserZwerg`, `SicherheitsZwerg`, `LeistungsZwerg`, `SEOZwerg`, `ZugaenglichkeitsZwerg`, `InhaltZwerg`, `VisualZwerg`).
-   **Base Framework**: `Dwarf`, `Issue`, `AnalysisResult` classes for structured findings.
-   **CLI Interface**: `Typer`-based command-line interface for user interaction.
-   **Configuration**: Settings management with `Pydantic`.

### Key Features (Phase 3 Complete)

-   **Core Web Vitals & Performance Monitoring**: LCP, FCP, CLS measurement.
-   **Advanced Security Scanning**: Port scanning, service enumeration, vulnerability detection.
-   **Enhanced Accessibility**: WCAG 2.1 AA, EU/EAA compliance, ARIA testing.
-   **Mobile & Responsive Testing**: Viewport analysis, touch targets, screenshots.
-   **Visual Analysis & UI Testing**: Consistency, elements, colors, layout analysis.
-   **LLM Integration**: LLM-powered issue classification, prioritization, fix suggestions, natural language reporting, and cost tracking.

### `check` vs `analyze` Commands

-   **`check`**: Performs a fast, basic website quality check, outputting simple `Issue` objects. Suitable for quick health checks.
-   **`analyze`**: Conducts an in-depth analysis designed for LLM integration, outputting rich `DetailedIssue` objects with extensive context (code locations, fix suggestions, business impact, raw data). This command is crucial for LLM-powered insights.

## System Dependencies

The project requires the `nmap` binary to be installed on the system for advanced security scanning.

-   On macOS: `brew install nmap`
-   On Ubuntu/Debian: `sudo apt install nmap`
-   On Fedora: `sudo dnf install nmap`

Ensure `nmap` is available in your PATH.

## Testing Strategy

-   **Unit tests**: For individual Dwarf agents.
-   **Integration tests**: For CLI and orchestration logic.
-   **Mock-based testing**: For external dependencies.
-   **Real browser testing**: Utilizing Playwright.
-   **Security testing**: In controlled environments.
-   **Accessibility testing**: With WCAG compliance checks.
