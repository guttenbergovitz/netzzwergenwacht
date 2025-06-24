"""Integration tests for CLI functionality."""

from netzzwergenwacht.cli.main import app
from typer.testing import CliRunner

runner = CliRunner()


class TestCLI:
    """Test CLI commands."""

    def test_version_command(self):
        result = runner.invoke(app, ["version"])
        assert result.exit_code == 0
        assert "NetzZwergenWacht" in result.stdout
        assert "Version:" in result.stdout

    def test_check_command_with_valid_url(self):
        result = runner.invoke(app, ["check", "https://example.com"])
        assert result.exit_code == 0
        assert "Analyzing:" in result.stdout
        assert "Web-Browser-Zwerg" in result.stdout

    def test_check_command_with_invalid_url(self):
        result = runner.invoke(app, ["check", "not-a-url"])
        assert result.exit_code == 0
        assert "Invalid Url Scheme" in result.stdout

    def test_check_command_verbose(self):
        result = runner.invoke(app, ["check", "https://example.com", "--verbose"])
        assert result.exit_code == 0
        assert "Analyzing:" in result.stdout

    def test_monitor_command_placeholder(self):
        result = runner.invoke(app, ["monitor", "config.yaml"])
        assert result.exit_code == 0
        assert "not yet implemented" in result.stdout

    def test_all_zwerge_active(self):
        """Test that all 6 Zwerge are active in CLI analysis."""
        result = runner.invoke(app, ["check", "https://example.com", "--verbose"])
        assert result.exit_code == 0

        # Check that all 6 Zwerge are present in output
        expected_zwerge = [
            "Web-Browser-Zwerg",
            "Sicherheits-Zwerg",
            "Leistungs-Zwerg",
            "SEO-Zwerg",
            "Zugaenglichkeits-Zwerg",
            "Inhalt-Zwerg",
        ]

        for zwerg in expected_zwerge:
            assert zwerg in result.stdout, f"Missing {zwerg} in CLI output"
