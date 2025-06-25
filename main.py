"""Backward compatibility entry point for the CLI."""

import sys
import warnings
from importlib.metadata import version

try:
    from netzzwergenwacht.cli.main import app
except ImportError:
    from src.netzzwergenwacht.cli.main import app  # Fallback for dev


def show_deprecation_warning():
    """Show deprecation warning for legacy entry point."""
    warnings.warn(
        "Legacy main.py entry point is deprecated and will be removed in v1.0. "
        f"Use 'netzzwergenwacht' (v{version('netzzwergenwacht')}) instead.",
        DeprecationWarning,
        stacklevel=2,
    )
    print("⚠️  Deprecation Warning: Using legacy entry point")


def main():
    """Legacy main function - redirects to new CLI."""
    show_deprecation_warning()

    try:
        app()
    except Exception as e:
        print(f"Error: {str(e)}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
