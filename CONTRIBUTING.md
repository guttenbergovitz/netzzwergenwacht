# Contributing to NetzZwergenWacht

## Development Setup

1. **Clone the repository**
   ```bash
   git clone https://github.com/guttenbergovitz/netzzwergenwacht.git
   cd netzzwergenwacht
   ```

2. **Install dependencies**
   ```bash
   uv sync --dev
   ```

3. **Install pre-commit hooks**
   ```bash
   uv run pre-commit install
   ```

## Development Workflow

### Running Tests
```bash
# Run all tests
uv run pytest

# Run with coverage
uv run pytest --cov=src

# Run specific test
uv run pytest tests/unit/test_dwarfs/test_base.py
```

### Code Quality
```bash
# Run linter
uv run ruff check

# Format code
uv run ruff format

# Type checking
uv run mypy src/
```

### Running the CLI
```bash
# Using the package script
uv run netzzwergenwacht --help

# Using the short alias
uv run nzw --help

# Direct execution
uv run python -m netzzwergenwacht.cli.main --help

# LLM-powered analysis (requires OPENAI_API_KEY)
uv run nzw analyze https://example.com --llm

# Multi-agent CrewAI analysis
uv run nzw analyze https://example.com --agents
```

## Architecture

The project follows a modular architecture with distinct responsibilities:

- **`dwarfs/`** - Core analysis agents (Zwerge)
- **`agents/`** - CrewAI multi-agent system with 11 specialized experts
- **`analyzers/`** - Specific quality check implementations
- **`cli/`** - Command-line interface
- **`config/`** - Configuration management
- **`llm/`** - LLM integration and OpenAI API handling
- **`reporting/`** - Output formatting and reports (JSON, PDF)
- **`utils/`** - Shared utilities and logging

## Adding New Dwarfs

1. Create a new class inheriting from `Dwarf`
2. Implement both `analyze()` and `analyze_detailed()` methods
3. Add tests in `tests/unit/test_dwarfs/`
4. Register in the orchestrator

Example:
```python
from netzzwergenwacht.dwarfs.base import Dwarf, AnalysisResult, DetailedAnalysisResult

class MyDwarf(Dwarf):
    def __init__(self):
        super().__init__("My Dwarf", "Description")

    async def analyze(self, url: str) -> AnalysisResult:
        # Basic analysis implementation
        pass

    async def analyze_detailed(self, url: str) -> DetailedAnalysisResult:
        # Detailed analysis for LLM integration
        pass
```

## LLM Integration Development

When working with LLM features:

1. **Environment Setup**:
   ```bash
   export OPENAI_API_KEY="your-api-key-here"
   ```

2. **Testing LLM Features**:
   ```bash
   # Test single LLM analysis
   uv run nzw analyze https://example.com --llm

   # Test multi-agent CrewAI analysis
   uv run nzw analyze https://example.com --agents
   ```

3. **CrewAI Agent Development**:
   - Located in `src/netzzwergenwacht/agents/`
   - 11 specialized agents with distinct roles
   - Collaborative task execution with shared context

## Code Style

- Use type hints for all function signatures
- Follow PEP 8 conventions
- Maximum line length: 88 characters
- Use meaningful variable and function names
- Write docstrings for public methods

## Commit Guidelines

- Use conventional commit format: `type(scope): description`
- Types: `feat`, `fix`, `docs`, `style`, `refactor`, `test`, `chore`
- Keep commits focused and atomic
- Write clear commit messages

## Pull Request Process

1. Create a feature branch from `main`
2. Make your changes with tests
3. Ensure all tests pass and code is formatted
4. Update documentation if needed
5. Submit PR with clear description
