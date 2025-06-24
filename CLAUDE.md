# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

NetzZwergenWacht is an intelligent, automated system for analyzing and monitoring website quality using LLM-powered software agents called "Dwarfs". The system performs automated E2E interactions, comprehensive quality analysis, and generates intelligent reports with LLM insights. The project has completed **Phase 2** and is now moving to **Phase 3** with LLM integration.

## Technology Stack

- **Language**: Python (requires >=3.12)
- **Project Management**: uv
- **Browser Automation**: Playwright (implemented)
- **HTTP Client**: httpx
- **HTML Parsing**: BeautifulSoup
- **Security Scanning**: nmap, safety
- **Testing**: pytest
- **Linting**: ruff
- **Type Checking**: mypy

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

The project has completed **Phase 2** and is now in **Phase 3** with a comprehensive modular architecture:

### Core Components

- **Dwarf Agents**: Modular analysis components
  - `WebBrowserZwerg` - Browser automation with Playwright, mobile/responsive emulacja, screenshoty
  - `SicherheitsZwerg` - Security analysis and vulnerability scanning
  - `ZugaenglichkeitsZwerg` - Accessibility compliance (WCAG 2.1 AA, EU/EAA), mobile/responsive checks
  - `LeistungsZwerg` - Performance analysis and Core Web Vitals
  - `SEOZwerg` - Search engine optimization analysis
  - `InhaltZwerg` - Content quality and readability analysis
  - `VisualZwerg` - Visual analysis and UI testing (consistency, elements, colors, layout, screenshots)

- **Base Framework**: `Dwarf`, `Issue`, `AnalysisResult` classes
- **CLI Interface**: Typer-based command line interface
- **Configuration**: Settings management with Pydantic

### Phase 1 Completed Features

#### Browser Automation (WebBrowserZwerg)
- **Playwright integration** for real browser automation
- **JavaScript console error detection**
- **Network request failure monitoring**
- **Browser-based accessibility validation**
- **Real user journey simulation**

#### Core Analysis Modules
- **Security analysis** (SSL, headers, vulnerabilities)
- **Performance monitoring** (response times, resource usage)
- **SEO analysis** (meta tags, structured data, content quality)
- **Accessibility compliance** (WCAG 2.1 AA, EU Accessibility Act)
- **Content quality** (readability, structure, language)

### Phase 2 Completed Features

#### Advanced Security Scanning (SicherheitsZwerg)
- **Port scanning** with nmap integration (TCP connect scan, no root required)
- **Service enumeration** and database exposure detection
- **Information disclosure** checks (robots.txt, .env, .git, etc.)
- **Dangerous port detection** (FTP, Telnet, database ports)
- **Security misconfiguration** identification

#### Enhanced ARIA & Accessibility Compliance (ZugaenglichkeitsZwerg)
- **Form ARIA accessibility** (WCAG 3.3.2 - Labels or Instructions)
- **Live regions** (WCAG 4.1.3 - Status Messages)
- **Interactive elements** (WCAG 2.1.1 - Keyboard)
- **Navigation ARIA** (WCAG 2.4.1 - Bypass Blocks)
- **Error handling** (WCAG 3.3.1 - Error Identification)

#### Core Web Vitals & Performance Monitoring (LeistungsZwerg)
- **LCP (Largest Contentful Paint)** measurement using Playwright
- **FCP (First Contentful Paint)** analysis
- **CLS (Cumulative Layout Shift)** detection
- **System resource monitoring** (CPU, memory usage)
- **Performance thresholds** and recommendations

#### Mobile & Responsive Testing (ZugaenglichkeitsZwerg, WebBrowserZwerg)
- **Viewport meta** tag detection and validation
- **Touch target size** and spacing analysis
- **Responsive breakpoints** and media query detection
- **Font size** checks for mobile readability
- **Horizontal scroll** and fixed positioning detection
- **Modern layout** (flexbox/grid) usage validation
- **Image optimization** for mobile
- **Automated screenshots** for mobile, tablet, desktop viewports (output/ directory)

#### Visual Analysis & UI Testing (VisualZwerg)
- **Visual consistency** analysis (spacing, fonts, layout patterns)
- **UI element detection** (buttons, forms, navigation structures)
- **Color scheme analysis** and contrast validation
- **Layout issues** detection (overlapping elements, overflow problems)
- **Screenshot analysis** with automated capture and processing
- **Interactive element testing** and accessibility validation
- **Visual regression testing** capabilities

### Phase 3 In Progress Features

#### LLM Integration & Intelligence
- **LLM-powered issue classification** and prioritization
- **Intelligent recommendations** and actionable insights
- **Natural language reporting** with context-aware analysis
- **Automated issue resolution** suggestions
- **Smart issue correlation** and pattern recognition

### API Testing Decision

**API Testing & Integration was intentionally skipped** in Phase 2 due to limited value for external testing:

#### Why API Testing was skipped:
- **Limited scope**: External testing can only access public endpoints
- **Authentication barriers**: Most APIs require keys/tokens not available externally
- **Ethical concerns**: Performance testing could be seen as DDoS attacks
- **False positives**: Shallow testing may generate misleading results
- **Limited business value**: External API testing provides minimal actionable insights

#### What was considered:
- **Health check endpoints** (`/health`, `/status`, `/ping`)
- **Documentation discovery** (OpenAPI/Swagger)
- **Security headers** analysis
- **Public endpoint** testing

#### Future consideration:
API testing may be revisited in Phase 4/5 if internal testing capabilities are added.

## System Dependencies

This project requires the `nmap` binary to be installed on your system for advanced security scanning (port scanning). The Python package `python-nmap` is only a wrapper and does not install the actual `nmap` binary.

- On macOS: `brew install nmap`
- On Ubuntu/Debian: `sudo apt install nmap`
- On Fedora: `sudo dnf install nmap`

Make sure `nmap` is available in your PATH.

## Development Phases

The project follows a phased approach:

- **✅ Phase 0**: Foundation & Setup (completed)
- **✅ Phase 1**: Core Browser Interaction & Basic Analysis (completed)
- **✅ Phase 2**: Advanced Analysis Features (completed)
  - ✅ Core Web Vitals & Performance Monitoring
  - ✅ Advanced Security Scanning
  - ✅ Enhanced ARIA & Accessibility Compliance
  - ✅ Mobile & Responsive Testing
  - ✅ Visual Analysis & UI Testing
  - ✅ ~~API Testing & Integration~~ (skipped - limited value for external testing)
- **🔄 Phase 3**: LLM Integration (in progress)
  - 🔄 LLM-powered issue classification
  - 🔄 Intelligent recommendations
  - 🔄 Natural language reporting
  - 🔄 Context-aware analysis
- **📋 Phase 4**: Enhanced Reporting & Actions (planned)
- **📋 Phase 5**: Configuration, Scheduling & Usability (planned)

## Key Design Principles

- **LLM-powered intelligent analysis** and classification
- **Modular "Dwarf" agent architecture** for extensibility
- **EU/EAA compliance** for accessibility standards
- **Comprehensive security scanning** with industry tools
- **Real browser automation** for realistic user journey simulation
- **Configurable and scheduled monitoring**
- **Clear reporting with actionable insights**
- **Modern Python practices** (type hints, async/await, dependency injection)

## Testing Strategy

- **Unit tests** for each Dwarf agent
- **Integration tests** for CLI and orchestration
- **Mock-based testing** for external dependencies
- **Real browser testing** with Playwright
- **Security testing** with controlled environments
- **Accessibility testing** with WCAG compliance checks
