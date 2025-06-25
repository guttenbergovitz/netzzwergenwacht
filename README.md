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

## 🎯 Current Status: Phase 2 Complete ✅

**Phase 2 has been successfully completed!** All major advanced analysis features have been implemented:

- ✅ **Core Web Vitals & Performance Monitoring** - LCP, FCP, CLS measurement
- ✅ **Advanced Security Scanning** - Port scanning, service enumeration, vulnerability detection
- ✅ **Enhanced Accessibility** - WCAG 2.1 AA, EU/EAA compliance, ARIA testing
- ✅ **Mobile & Responsive Testing** - Viewport analysis, touch targets, screenshots
- ✅ **Visual Analysis & UI Testing** - Consistency, elements, colors, layout analysis

### 🔄 Phase 3 - LLM Integration (in progress)

- [x] Detailed analysis mode for all Zwerge
- [x] LLM-ready output structure (JSON)
- [x] CLI support for analyze command
- [ ] LLM-powered classification, prioritization, and fix suggestion (in progress)
- [ ] Natural language reporting (in progress)
- [ ] Automated issue correlation (in progress)

## 🤔 API Testing Decision

**API Testing & Integration was intentionally skipped** in Phase 2 due to limited value for external testing:

### Why API Testing was skipped:
- **Limited scope**: External testing can only access public endpoints
- **Authentication barriers**: Most APIs require keys/tokens not available externally
- **Ethical concerns**: Performance testing could be seen as DDoS attacks
- **False positives**: Shallow testing may generate misleading results
- **Limited business value**: External API testing provides minimal actionable insights

### What was considered:
- **Health check endpoints** (`/health`, `/status`, `/ping`)
- **Documentation discovery** (OpenAPI/Swagger)
- **Security headers** analysis
- **Public endpoint** testing

### Future consideration:
API testing may be revisited in Phase 4/5 if internal testing capabilities are added.

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

### Phase 2: Advanced Analysis Features ✅ **COMPLETED**
- [x] **Enhanced Performance Metrics** - Core Web Vitals (LCP, FCP, CLS) with browser automation
- [x] **Advanced Security Scanning** - Port scanning, service enumeration, vulnerability detection
- [x] **Enhanced ARIA & Accessibility Compliance** - WCAG 2.1 AA, EU/EAA standards
- [x] **Mobile & Responsive Testing** - Viewport analysis, touch targets, breakpoints, screenshots
- [x] **Visual Analysis & UI Testing** - Consistency, elements, colors, layout analysis
- [x] ~~API Testing & Integration~~ (skipped - limited value for external testing)

### Phase 3: Intelligence & Automation 🔄 **IN PROGRESS**
- [x] Detailed analysis mode for all Zwerge
- [x] LLM-ready output structure (JSON)
- [x] CLI support for analyze command
- [ ] LLM-powered classification, prioritization, and fix suggestion (in progress)
- [ ] Natural language reporting (in progress)
- [ ] Automated issue correlation (in progress)

### Phase 4: Enterprise Features 📋 **PLANNED**
- [ ] Multi-site Monitoring - Batch analysis and reporting
- [ ] Custom Rule Engine - User-defined analysis rules
- [ ] Integration APIs - REST API for external integrations
- [ ] Advanced Reporting - PDF reports, dashboards, alerts

### Phase 5: Advanced Intelligence 📋 **PLANNED**
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

## 🧠 Detailed Analysis & LLM Integration (Phase 3)

NetzZwergenWacht now supports a new **detailed analysis mode** for all Zwerge, designed for seamless LLM integration and advanced reporting.

- Each Zwerg implements an `analyze_detailed` method, returning a `DetailedAnalysisResult` with:
  - Rich, structured issues (with code location, fix suggestions, affected elements, priority, and context)
  - Metrics specific to the analysis type (performance, security, accessibility, content, visual, SEO)
  - Raw data for LLMs (HTML, screenshots, network traces, etc.)
- The CLI provides an `analyze` command that runs all Zwerge in detailed mode and saves a comprehensive, LLM-ready JSON report in the `output/` directory.
- This enables:
  - LLM-powered issue classification, prioritization, and fix suggestion
  - Natural language reporting and context-aware analysis
  - Automated correlation of issues across all quality dimensions

### Example Output Structure

```json
{
  "url": "https://example.com",
  "dwarf_name": "Leistungs-Zwerg",
  "detailed_issues": [
    {
      "issue_type": "page_load_very_slow",
      "severity": "high",
      "message": "Page load time is very slow: 6500ms",
      "category": "performance",
      "subcategory": "page_load_time",
      "description": "Page takes more than 5 seconds to load, which severely impacts user experience",
      "impact": "Users will likely abandon the page, affecting conversion rates and SEO",
      "technical_details": {"load_time_ms": 6500, "recommended_max_ms": 3000},
      "recommendations": ["Optimize page load performance immediately"],
      "fix_suggestions": ["Enable server-side caching", "Optimize and compress images"],
      "priority_score": 0.9,
      "code_location": {"resource_type": "http", "attribute_value": "https://example.com"},
      "affected_elements": ["server_config", "assets", "caching"]
    }
  ],
  "performance_metrics": {
    "page_load_time_ms": 6500,
    "lcp": 4200,
    "fcp": 1800,
    "cls": 0.12
  },
  "raw_data": {"performance": {"response_status": 200, ...}}
}
```

### How to Use

- Run detailed analysis:
  ```bash
  uv run nzw analyze https://example.com
  # or
  uv run netzzwergenwacht analyze https://example.com
  ```
- Find the LLM-ready JSON report in the `output/` directory.
- Use this output for downstream LLM processing, reporting, or integration with other tools.

### Phase 3 Progress

- [x] Detailed analysis mode for all Zwerge
- [x] LLM-ready output structure (JSON)
- [x] CLI support for analyze command
- [ ] LLM-powered classification, prioritization, and fix suggestion (in progress)
- [ ] Natural language reporting (in progress)
- [ ] Automated issue correlation (in progress)

---

*Built with ❤️ using modern Python practices and designed for extensibility.*
# NetzZwergenWacht

[![Python Version](https://img.shields.io/badge/python-3.12+-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Code style: ruff](https://img.shields.io/badge/code%20style-ruff-000000.svg)](https://github.com/astral-sh/ruff)

Intelligent website quality monitoring using LLM-powered Dwarfs (analysis agents).

## 🚀 Features

- **Comprehensive Analysis**:
  - ✅ Performance (Core Web Vitals, load times)
  - 🔒 Security (SSL, headers, vulnerabilities)
  - 🔍 SEO (meta tags, structure, content)
  - ♿ Accessibility (WCAG 2.1, EAA)
  - 📝 Content quality & readability
  - 🎨 Visual consistency & UI checks

- **Advanced Capabilities**:
  - Configurable via ENV/.env files
  - JSON logging support
  - Detailed analysis mode for LLM integration
  - Customizable checks per Dwarf
  - Rich CLI output

## 📦 Installation

```bash
pip install netzzwergenwacht
```

For JSON logging support:
```bash
pip install netzzwergenwacht[json-logging]
```

## 🛠️ Basic Usage

### Quick Check
```bash
nzw check https://example.com
```

### Detailed Analysis (LLM-ready)
```bash
nzw analyze https://example.com --output report.json
```

### Monitor Mode
```bash
nzw monitor config.yaml
```

## ⚙️ Configuration

Create `.env` file:
```ini
# Core Settings
NZW_LOG_LEVEL=INFO  # DEBUG, INFO, WARNING, ERROR
NZW_LOG_FORMAT=rich # rich, json, plain
NZW_MAX_WORKERS=10  # Concurrent analysis threads

# Security Settings
NZW_SCAN_PORTS=true
NZW_ALLOW_INSECURE=false

# Dwarf-specific
NZW_DWARFS__WEB_BROWSER_ZWERG__TIMEOUT=30
NZW_DWARFS__SICHERHEITS_ZWERG__SCAN_PORTS=true
```

## 🧑‍💻 Development

### Setup
```bash
git clone https://github.com/guttenbergovitz/netzzwergenwacht.git
cd netzzwergenwacht
pip install -e .[dev]
pre-commit install
```

### Testing
```bash
pytest -v --cov=src --cov-report=html
```

### Code Quality
```bash
ruff check src
ruff format src
mypy src
```

## 🧙 The Dwarf Brigade

| Dwarf | Purpose | Key Checks |
|-------|---------|------------|
| `WebBrowserZwerg` | Core browser analysis | HTTP status, performance, basic structure |
| `SicherheitsZwerg` | Security scanning | SSL, headers, vulnerabilities |
| `LeistungsZwerg` | Performance metrics | Core Web Vitals, load times |
| `SEOZwerg` | Search optimization | Meta tags, content structure |
| `ZugaenglichkeitsZwerg` | Accessibility | WCAG 2.1, EAA compliance |
| `InhaltZwerg` | Content quality | Readability, freshness, structure |
| `VisualZwerg` | UI/UX analysis | Visual consistency, color contrast |

## 📊 Sample Output

```bash
nzw check https://example.com --verbose
```

![Sample CLI Output](https://example.com/sample-output.png) *(placeholder image)*

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit changes (`git commit -m 'Add amazing feature'`)
4. Push to branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

See [CONTRIBUTING.md](CONTRIBUTING.md) for detailed guidelines.

## 📜 License

MIT - See [LICENSE](LICENSE) for details.

## 📬 Contact

- Author: GTBGZ
- Email: guttenbergovitz@gmail.com
- GitHub: [@guttenbergovitz](https://github.com/guttenbergovitz)
