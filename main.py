"""Backward compatibility entry point for the CLI."""

from src.netzzwergenwacht.cli.main import app


def main():
    """Legacy main function - redirects to new CLI."""
    print(
        "⚠️  Using legacy main.py - consider using 'netzzwergenwacht' or 'nzw' command instead"
    )
    app()


if __name__ == "__main__":
    main()
