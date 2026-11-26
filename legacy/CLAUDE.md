# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

NetzZwergenWacht is an intelligent, automated system for analyzing and monitoring website quality using LLM-powered software agents called "Dwarfs". The system performs automated E2E interactions, comprehensive quality analysis, and generates intelligent reports with LLM insights. The project has completed **Phase 3** with full LLM integration.

## Technology Stack

- **Language**: Python (requires >=3.12)
- **Project Management**: uv
- **Browser Automation**: Playwright (implemented)
- **HTTP Client**: httpx
- **HTML Parsing**: BeautifulSoup
- **Security Scanning**: nmap, safety
- **LLM Integration**: OpenAI API (requires OPENAI_API_KEY environment variable)
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
# Quick check a website
uv run nzw check https://example.com

# Comprehensive analysis with LLM integration
uv run nzw analyze https://example.com --llm

# Advanced multi-agent CrewAI analysis
uv run nzw analyze https://example.com --agents

# Check with verbose output
uv run nzw check https://example.com --verbose

# Save results to file
uv run nzw check https://example.com --output results.json --format json

# Show version
uv run nzw version
```

### LLM-Powered Analysis
```bash
# Set up OpenAI API key for enhanced analysis
export OPENAI_API_KEY="your-api-key-here"

# Run comprehensive single LLM analysis with intelligent insights
uv run nzw analyze https://example.com --llm

# Run advanced multi-agent CrewAI analysis with 11 specialized experts
uv run nzw analyze https://example.com --agents

# This provides:
# - Single LLM: Specific technical fixes with exact code locations
# - Multi-agent: 11 AI experts collaborating (Security, Performance, Accessibility, etc.)
# - Executive-level strategic recommendations and implementation roadmaps
# - Copy-paste ready solutions and configuration changes
# - Business impact assessments with priority scoring
# - Real-time cost tracking and token usage monitoring
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

The project has completed **Phase 3** with comprehensive LLM integration and a modular architecture:

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

### Phase 3 Completed Features ✅

#### LLM Integration & Intelligence
- **✅ LLM-powered issue classification** and prioritization with OpenAI integration
- **✅ Intelligent recommendations** with specific technical fixes and exact code
- **✅ Natural language reporting** with detailed location context and implementation guides
- **✅ Automated issue resolution** suggestions with copy-paste ready solutions
- **✅ Smart issue correlation** and priority scoring across all quality dimensions
- **✅ Cost tracking and model information** display with real-time usage monitoring
- **✅ Enhanced error handling** and fallback mechanisms for robust operation

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

## LLM Integration Setup

For LLM-powered analysis capabilities, you need to set up OpenAI API access:

```bash
# Set your OpenAI API key
export OPENAI_API_KEY="your-api-key-here"

# Or add to .env file
echo "OPENAI_API_KEY=your-api-key-here" >> .env
```

The LLM integration provides enhanced analysis insights, intelligent issue prioritization, and natural language recommendations.

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
- **✅ Phase 3**: LLM Integration (completed)
  - ✅ OpenAI API integration with cost tracking
  - ✅ CrewAI multi-agent system with 11 specialized domain experts
  - ✅ Single LLM (`--llm`) and multi-agent (`--agents`) analysis modes
  - ✅ LLM processor for comprehensive report analysis
  - ✅ LLM-powered issue classification and prioritization
  - ✅ Intelligent recommendations with specific technical fixes
  - ✅ Executive-level strategic analysis and implementation roadmaps
  - ✅ Natural language reporting with exact code locations
  - ✅ Context-aware analysis with copy-paste ready solutions
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

## Phase 3: Detailed Analysis & LLM Integration

NetzZwergenWacht now features a **detailed analysis mode** for all Dwarf agents, designed for LLM integration and advanced, context-rich reporting.

- Each Dwarf implements an `analyze_detailed` method, returning a `DetailedAnalysisResult` with:
  - Structured issues (with code location, fix suggestions, affected elements, priority, and context)
  - Metrics specific to the analysis type (performance, security, accessibility, content, visual, SEO)
  - Raw data for LLMs (HTML, screenshots, network traces, etc.)
- The CLI provides an `analyze` command that runs all Dwarfs in detailed mode and saves a comprehensive, LLM-ready JSON report in the `output/` directory.
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

### How to Use LLM Features

```bash
# Set up OpenAI API key
export OPENAI_API_KEY="your-api-key-here"

# Run detailed analysis with single LLM integration
uv run nzw analyze https://example.com --llm

# Run advanced multi-agent CrewAI analysis
uv run nzw analyze https://example.com --agents

# Example LLM output:
# 🤖 LLM initialized with model: gpt-4o-mini
# 🔑 Using OpenAI API key: sk-1a2b3c...
# 📊 Sending request to gpt-4o-mini
# ✅ LLM Analysis Complete!
# Tokens used: 11389 ($0.0024)
#
# 📋 Detailed LLM Analysis:
# ## 2. Critical Issues Requiring Immediate Attention
# ### Issue 1: Missing Meta Description
# - **Exact Problem**: The page is missing a meta description tag.
# - **Location**: `<head>` section of the HTML.
# - **Immediate Fix**: Add the following code:
#   ```html
#   <meta name="description" content="A descriptive summary">
#   ```

# Example CrewAI multi-agent output:
# 🤖 CrewAI initialized with 11 specialized agents
# 👥 Security Expert, Performance Analyst, Accessibility Specialist...
# 📊 Multi-agent analysis in progress...
# ✅ CrewAI Analysis Complete!
# Tokens used: 24,567 ($0.0052)
#
# 📋 Executive Summary:
# Strategic recommendations with implementation roadmap
# Cross-domain issue correlation and priority matrix
# Business impact assessment with ROI projections
```

### LLM Integration Features

- **Enhanced Context**: LLM receives full technical details including exact HTML element locations, specific code fixes, priority scores, and business impact
- **Cost Tracking**: Real-time token usage and cost display with model information
- **Intelligent Analysis**: Provides specific technical fixes, implementation roadmaps, and copy-paste ready solutions
- **Fallback Mechanisms**: Graceful handling when LLM services are unavailable
- **Model Selection**: Uses economical gpt-4o-mini by default for cost-effective analysis

All Zwerge now support detailed analysis mode, making NetzZwergenWacht a powerful foundation for AI-driven website quality monitoring and automated remediation.

## Command Differences: `check` vs `analyze`

The system provides two distinct analysis modes with different purposes and output formats:

### `check` Command - Quick Analysis
- **Purpose**: Fast basic website quality check
- **Output**: Simple `Issue` objects with minimal context
- **Format**: Human-readable CLI output or basic JSON
- **Use Case**: Quick health checks, CI/CD pipelines, automated monitoring
- **Features**: Identifies problems with basic severity and location information

### `analyze` Command - Comprehensive Analysis
- **Purpose**: In-depth analysis designed for LLM integration and detailed reporting
- **Output**: Rich `DetailedIssue` objects with extensive context
- **Format**: LLM-ready JSON with full technical details
- **Use Case**: Development teams, security audits, comprehensive quality assessments
- **Features**:
  - Exact code locations with `CodeLocation` objects
  - Detailed fix suggestions with copy-paste ready solutions
  - Business impact analysis and priority scoring
  - Implementation roadmaps and step-by-step guides
  - Raw data capture (HTML, screenshots, network traces)
  - Optional single LLM processing with `--llm` flag
  - Optional multi-agent CrewAI analysis with `--agents` flag

### Analysis Mode Options

**`analyze`**: Generates detailed JSON report for manual review or custom processing
**`analyze --llm`**: Single LLM analysis with intelligent insights and technical fixes
**`analyze --agents`**: Multi-agent CrewAI collaboration with 11 specialized domain experts

### Example Difference

**`check` finds**: "Missing meta description"
**`analyze` finds**: "Missing meta description" + exact location in HTML + concrete fix suggestions + business impact + priority score + implementation steps
**`analyze --llm` adds**: LLM-powered intelligent analysis with context-aware recommendations
**`analyze --agents` adds**: Multi-agent collaboration with strategic executive summary and cross-domain issue correlation

The `analyze` command is specifically designed for **Phase 3 LLM integration** and provides the structured, detailed data that enables intelligent AI-powered recommendations.
