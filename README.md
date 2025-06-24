# NetzZwergenWacht

[![Python 3.12+](https://img.shields.io/badge/python-3.12+-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Code style: ruff](https://img.shields.io/badge/code%20style-ruff-000000.svg)](https://github.com/astral-sh/ruff)

> **Intelligent website quality monitoring using LLM-powered Dwarfs**

NetzZwergenWacht is an automated system for analyzing and monitoring website quality. It employs "Zwerge" (German-named dwarfs) – intelligent software agents – to perform comprehensive checks, identify issues, and provide actionable insights to development teams.

## 🚀 Quick Start

### Installation & Setup

```bash
# Clone the repository
git clone https://github.com/guttenbergovitz/netzzwergenwacht.git
cd netzzwergenwacht

# Install dependencies
uv sync

# Install development dependencies (optional)
uv sync --dev

# Install pre-commit hooks (for contributors)
uv run pre-commit install
```

### Basic Usage

```bash
# Check a website for quality issues
uv run netzzwergenwacht check https://example.com

# Use the short alias
uv run nzw check https://example.com

# Verbose output with detailed information
uv run nzw check https://example.com --verbose

# Save results to a file
uv run nzw check https://example.com --output results.txt

# Show version information
uv run nzw version
```

## 🏗️ Architecture

NetzZwergenWacht follows a modular architecture designed for extensibility and maintainability:

```
src/netzzwergenwacht/
├── cli/                    # Command-line interface
├── dwarfs/                # Core analysis agents (Zwerge)
│   ├── base.py            # Base classes and abstractions
│   ├── web_browser_zwerg.py # Web-Browser-Zwerg agent
│   ├── sicherheits_zwerg.py # Sicherheits-Zwerg agent
│   └── leistungs_zwerg.py # Leistungs-Zwerg agent
├── analyzers/             # Specific quality check implementations
├── config/                # Configuration management
├── llm/                  # LLM integration (future)
├── reporting/            # Output formatting and reports
└── utils/                # Shared utilities and logging
```

### Core Concepts

- **Zwerge (Dwarfs)**: Intelligent German-named agents that perform specific types of analysis
- **Issues**: Structured findings with severity levels and evidence
- **Orchestrator**: Coordinates multiple Zwerge for comprehensive analysis
- **Rich CLI**: User-friendly command-line interface with colored output

### 🧙‍♂️ Die Zwergen-Brigade (The Dwarf Brigade)

Our analysis agents follow German naming conventions as our signature branding:

#### Currently Active:
- **`Web-Browser-Zwerg`** - Analyzes websites for HTTP status, performance and basic structure
  - HTTP status checking (4xx/5xx errors, redirects)
  - Response time monitoring (flags >2s moderate, >5s slow)
  - HTML structure validation (title, meta descriptions)
  - Basic SEO analysis (title length, H1 tags)
  - Accessibility checks (alt text, lang attributes)

- **`Sicherheits-Zwerg`** - Security analysis for SSL certificates, headers and vulnerabilities
  - SSL/TLS certificate validation and expiry checking
  - Security headers analysis (HSTS, CSP, X-Frame-Options, etc.)
  - HTTPS enforcement validation
  - Cipher strength and protocol version checking
  - Information disclosure detection

- **`Leistungs-Zwerg`** - Performance analysis for load times, resource optimization and Core Web Vitals
  - Page load time monitoring with performance thresholds
  - Content size analysis and compression detection
  - Resource optimization checks (CSS, JS, images)
  - Caching header validation
  - Render-blocking resource detection
  - External resource dependency analysis

#### Planned Zwerge:
- **`Zugaenglichkeits-Zwerg`** - Accessibility testing (WCAG compliance, screen reader compatibility)
- **`SEO-Zwerg`** - Search engine optimization (meta tags, structured data, keyword analysis)
- **`Inhalt-Zwerg`** - Content quality analysis (readability, grammar, duplicate content)
- **`Mobile-Zwerg`** - Mobile-specific testing (responsive design, touch targets, viewport)

## 🎯 Current Status: Phase 0 Complete ✅

### ✅ Foundation & Setup (Phase 0)
- [x] Git repository and project structure
- [x] Modern Python packaging with `uv`
- [x] Comprehensive test suite (25 tests passing)
- [x] Code quality tools (ruff, mypy, pre-commit)
- [x] Rich CLI with Typer
- [x] Modular architecture with base abstractions
- [x] Configuration management with Pydantic
- [x] Documentation and contributing guidelines

### 🎯 Next: Phase 1 - Core Browser Interaction

The foundation is now ready for implementing actual browser automation:

1. **Playwright Integration** - Add browser automation capabilities
2. **Page Information Gathering** - Retrieve titles, meta data, basic metrics
3. **Enhanced Browser Dwarf** - Implement real web page analysis
4. **Error Handling** - Robust browser operation error management

## 🧪 Development

### Running Tests

```bash
# Run all tests
uv run pytest

# Run with coverage
uv run pytest --cov=src

# Run specific test file
uv run pytest tests/unit/test_dwarfs/test_base.py
```

### Code Quality

```bash
# Lint code
uv run ruff check

# Format code
uv run ruff format

# Type checking
uv run mypy src/

# Run all quality checks
uv run ruff check && uv run ruff format && uv run mypy src/ && uv run pytest
```

### Adding New Zwerge

```python
from netzzwergenwacht.dwarfs.base import Dwarf, AnalysisResult, Severity

class SicherheitsZwerg(Dwarf):
    """Sicherheits-Zwerg - Analyzes websites for security vulnerabilities and best practices."""

    def __init__(self):
        super().__init__("Sicherheits-Zwerg", "Security analysis for websites")

    async def analyze(self, url: str) -> AnalysisResult:
        issues = []

        # Perform security analysis here
        # Add issues using self.create_issue()

        return AnalysisResult(
            url=url,
            dwarf_name=self.name,
            issues=issues
        )
```

## 🎯 Roadmap

### Phase 1: Core Browser Interaction
- Playwright integration for browser automation
- Basic page information gathering
- Enhanced error handling

### Phase 2: Quality Analysis
- Broken link detection
- JavaScript console error capture
- Basic SEO and accessibility checks

### Phase 3: LLM Intelligence
- LLM provider integration
- Intelligent issue classification
- Context-aware analysis

### Phase 4: Enhanced Reporting
- Multiple output formats (JSON, HTML, Markdown)
- Alert system for critical issues
- Historical tracking

### Phase 5: Advanced Features
- Scheduled monitoring
- Custom check configurations
- CI/CD integration
- Web dashboard

## 🛠️ Technology Stack

- **Language**: Python 3.12+
- **Package Management**: uv
- **CLI Framework**: Typer with Rich console
- **Testing**: pytest with asyncio support
- **Code Quality**: ruff (linting & formatting), mypy (type checking)
- **Configuration**: Pydantic with environment variable support
- **Future**: Playwright (browser automation), LLM APIs

## 📚 Documentation

- [CONTRIBUTING.md](CONTRIBUTING.md) - Development guidelines and setup
- [CLAUDE.md](CLAUDE.md) - AI assistant guidance for working with the codebase

## 🤝 Contributing

We welcome contributions! Please see [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines on:

- Setting up the development environment
- Running tests and quality checks
- Code style and conventions
- Submitting pull requests

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 🔮 Vision

NetzZwergenWacht aims to become the go-to solution for automated website quality monitoring, combining the power of browser automation with LLM intelligence to provide actionable insights that help development teams maintain high-quality web applications.

---

*Built with ❤️ using modern Python practices and designed for extensibility.*
