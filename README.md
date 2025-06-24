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
│   ├── leistungs_zwerg.py # Leistungs-Zwerg agent
│   ├── seo_zwerg.py       # SEO-Zwerg agent
│   └── zugaenglichkeits_zwerg.py # Zugaenglichkeits-Zwerg agent
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
  - **Browser automation with Playwright** - Real browser analysis
  - JavaScript console error detection
  - Network request failure monitoring
  - Performance resource loading analysis
  - Browser-based accessibility validation
  - **Mobile & Responsive Testing**: Emulacja mobile/tablet/desktop, automatyczne screenshoty, wykrywanie problemów z viewportem, touch targets, fontami, przewijaniem

- **`Sicherheits-Zwerg`** - Security analysis for SSL certificates, headers and vulnerabilities
  - SSL/TLS certificate validation and expiry checking
  - Security headers analysis (HSTS, CSP, X-Frame-Options, etc.)
  - HTTPS enforcement and redirect analysis
  - Certificate chain validation
  - Security rating calculation

- **`Leistungs-Zwerg`** - Performance analysis for load times, resource optimization and Core Web Vitals
  - Page load time monitoring and threshold analysis
  - Resource optimization (images, CSS, JS)
  - Compression and caching header analysis
  - **Core Web Vitals measurement** - LCP, FCP, CLS with browser automation
  - **System resource monitoring** - CPU and memory usage tracking
  - Performance rating calculation
  - Resource timing analysis
  - Browser-based performance metrics

- **`SEO-Zwerg`** - Search Engine Optimization analysis
  - Meta tags analysis (title, description, keywords)
  - Heading structure validation (H1-H6 hierarchy)
  - Social media meta tags (Open Graph, Twitter Cards)
  - Structured data detection (JSON-LD, microdata)
  - Canonical URL analysis
  - Content quality assessment
  - Mobile optimization checks

- **`Zugaenglichkeits-Zwerg`** - Accessibility analysis following WCAG and EAA guidelines
  - WCAG 2.1 compliance checking (Level A, AA, AAA)
  - EAA (European Accessibility Act) requirements
  - Text alternatives for images
  - Color contrast analysis
  - Keyboard navigation support
  - Focus management
  - Semantic HTML structure
  - ARIA compliance
  - Screen reader compatibility
  - **Mobile & Responsive Checks**: Viewport meta, touch targets, breakpoints, font sizes, horizontal scroll, flexbox/grid, optymalizacja obrazów i zasobów

- **`Inhalt-Zwerg`** - Content quality and readability analysis
  - Content length and structure analysis
  - Readability scoring (Flesch-Kincaid, Flesch Reading Ease)
  - Duplicate content detection
  - Language quality assessment
  - Content freshness indicators
  - Heading structure validation
  - Content formatting analysis

- **`Visual-Zwerg`** - Visual analysis and UI testing
  - **Visual consistency** analysis (spacing, fonts, layout)
  - **UI element detection** (buttons, forms, navigation)
  - **Color scheme analysis** and contrast validation
  - **Layout issues** detection (overlapping elements, overflow)
  - **Screenshot analysis** with automated capture
  - **Interactive element testing** and accessibility
  - **Visual regression testing** capabilities

## 🎯 Current Status: Phase 1 Complete ✅

### ✅ Foundation & Setup (Phase 0)
- [x] Git repository and project structure
- [x] Modern Python packaging with `uv`
- [x] Comprehensive test suite (81 tests passing)
- [x] Code quality tools (ruff, mypy, pre-commit)
- [x] Rich CLI with Typer
- [x] Modular architecture with base abstractions
- [x] Configuration management with Pydantic
- [x] Documentation and contributing guidelines

### ✅ Core Browser Interaction (Phase 1)
- [x] **Playwright Integration** - Browser automation capabilities added
- [x] **Enhanced Web-Browser-Zwerg** - Real browser analysis with Playwright
- [x] **JavaScript Error Detection** - Console error monitoring
- [x] **Network Request Monitoring** - Failed request detection
- [x] **Performance Analysis** - Resource loading and timing metrics
- [x] **Browser-based Accessibility** - Real browser accessibility validation
- [x] **Error Handling** - Robust browser operation error management

### 🎯 Next: Phase 2 - Advanced Analysis Features

The browser automation foundation is now complete. Next steps include:

1. **Enhanced Performance Metrics** - Core Web Vitals, Lighthouse integration
2. **Advanced Security Scanning** - Vulnerability assessment, dependency checking
3. **Mobile Testing** - Responsive design validation, mobile-specific checks
4. **Screenshot & Visual Analysis** - Visual regression testing capabilities
5. **API Testing** - Endpoint validation and performance testing

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

### Automated Ruff Commit

You can use the provided helper script to automatically lint, format, stage and commit your changes in one go:

```bash
./ruff-commit.sh -m "Your commit message"
```

This script will:
- Run `ruff check --fix` to auto-fix lint issues
- Run `ruff format` to auto-format code
- Stage all changes (`git add .`)
- Commit with your message

This ensures your commit always passes the pre-commit ruff hook on the first try.

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

## 🗺️ Roadmap

### Phase 1: Core Browser Interaction ✅ **COMPLETED**
- [x] Playwright integration for browser automation
- [x] Enhanced Web-Browser-Zwerg with real browser analysis
- [x] JavaScript console error detection
- [x] Network request failure monitoring
- [x] Browser-based accessibility validation

### Phase 2: Advanced Analysis Features 🚧 **IN PROGRESS**
- [x] **Enhanced Performance Metrics** - Core Web Vitals (LCP, FCP, CLS) with browser automation
- [x] **System Resource Monitoring** - CPU and memory usage tracking
- [x] **Mobile & Responsive Testing** (viewport, touch targets, breakpoints, font sizes, screenshots)
- [x] **Visual Analysis & UI Testing** (consistency, elements, colors, layout, screenshots)
- [ ] API Testing - Endpoint validation and performance testing

### Phase 3: Intelligence & Automation
- [ ] LLM Integration - AI-powered analysis and recommendations
- [ ] Automated Fix Suggestions - Code-level optimization recommendations
- [ ] Trend Analysis - Historical performance tracking
- [ ] Predictive Analytics - Performance degradation prediction

### Phase 4: Enterprise Features
- [ ] Multi-site Monitoring - Batch analysis and reporting
- [ ] Custom Rule Engine - User-defined analysis rules
- [ ] Integration APIs - REST API for external integrations
- [ ] Advanced Reporting - PDF reports, dashboards, alerts

### Phase 5: Advanced Intelligence
- [ ] Machine Learning Models - Pattern recognition and anomaly detection
- [ ] Natural Language Reports - Human-readable analysis summaries
- [ ] Competitive Analysis - Benchmarking against industry standards
- [ ] Continuous Monitoring - Real-time website health monitoring

## 🛠️ Technology Stack

- **Language**: Python 3.12+
- **Package Management**: uv
- **CLI Framework**: Typer with Rich console
- **Testing**: pytest with asyncio support
- **Code Quality**: ruff (linting & formatting), mypy (type checking)
- **Configuration**: Pydantic with environment variable support
- **Browser Automation**: Playwright
- **Future**: LLM APIs

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

## System dependencies

This project requires the `nmap` binary to be installed on your system for advanced security scanning (port scanning). The Python package `python-nmap` is only a wrapper and does not install the actual `nmap` binary.

- On macOS: `brew install nmap`
- On Ubuntu/Debian: `sudo apt install nmap`
- On Fedora: `sudo dnf install nmap`

Make sure `nmap` is available in your PATH.

---

*Built with ❤️ using modern Python practices and designed for extensibility.*

## Phase 2: Advanced Analysis Features (In Progress)

### ✅ Completed Features

#### Core Web Vitals & Performance Monitoring
- **LCP (Largest Contentful Paint)** measurement using Playwright
- **FCP (First Contentful Paint)** analysis
- **CLS (Cumulative Layout Shift)** detection
- **System resource monitoring** (CPU, memory usage)
- **Performance thresholds** and recommendations

#### Advanced Security Scanning
- **Port scanning** with nmap integration (TCP connect scan, no root required)
- **Service enumeration** and database exposure detection
- **Information disclosure** checks (robots.txt, .env, .git, etc.)
- **Dangerous port detection** (FTP, Telnet, database ports)
- **Security misconfiguration** identification

#### Enhanced ARIA & Accessibility Compliance (EU/EAA Standards)
- **Form ARIA accessibility** (WCAG 3.3.2 - Labels or Instructions)
  - Form input labeling validation
  - Required field ARIA attributes
  - Label association checks
- **Live regions** (WCAG 4.1.3 - Status Messages)
  - Dynamic content accessibility
  - Appropriate aria-live usage
- **Interactive elements** (WCAG 2.1.1 - Keyboard)
  - Keyboard accessibility validation
  - Focus management for ARIA elements
- **Navigation ARIA** (WCAG 2.4.1 - Bypass Blocks)
  - Skip links detection
  - Heading structure validation
  - Landmark navigation
- **Error handling** (WCAG 3.3.1 - Error Identification)
  - Error message ARIA attributes
  - aria-invalid, aria-describedby validation

### 🔄 In Progress Features

#### Mobile Testing & Responsive Design
- Mobile viewport analysis
- Touch target size validation
- Responsive breakpoint testing

#### Visual Analysis & UI Testing
- Screenshot comparison
- Visual regression testing
- UI element detection

#### API Testing & Integration
- REST API endpoint discovery
- API response validation
- Integration testing capabilities

### 📋 Planned Features

#### Advanced Reporting & Analytics
- Trend analysis and historical data
- Custom report generation
- Performance benchmarking

#### Machine Learning Integration
- Automated issue classification
- Predictive maintenance
- Anomaly detection
