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
```

## Architecture

The project follows a modular architecture with distinct responsibilities:

- **`dwarfs/`** - Core analysis agents
- **`analyzers/`** - Specific quality check implementations
- **`cli/`** - Command-line interface
- **`config/`** - Configuration management
- **`llm/`** - LLM integration (future)
- **`reporting/`** - Output formatting and reports
- **`utils/`** - Shared utilities

## Adding New Dwarfs

1. Create a new class inheriting from `Dwarf`
2. Implement the `analyze()` method
3. Add tests in `tests/unit/test_dwarfs/`
4. Register in the orchestrator

Example:
```python
from netzzwergenwacht.dwarfs.base import Dwarf, AnalysisResult

class MyDwarf(Dwarf):
    def __init__(self):
        super().__init__("My Dwarf", "Description")

    async def analyze(self, url: str) -> AnalysisResult:
        # Implementation here
        pass
```

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
