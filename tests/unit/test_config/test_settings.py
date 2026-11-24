"""Tests for settings configuration."""

from netzzwergenwacht.config.settings import Settings, get_settings


class TestSettings:
    """Test Settings class."""

    def test_default_values(self):
        settings = Settings()

        assert settings.browser_headless
        assert settings.browser_timeout == 30000
        assert settings.llm_provider == "openai"
        assert settings.llm_model == "gpt-4"
        assert settings.default_checks == ["links", "console", "seo"]
        assert settings.max_concurrent_checks == 5
        assert settings.output_format == "console"
        assert settings.log_level == "INFO"

    def test_env_prefix(self):
        # Test that environment variables with NZW_ prefix are recognized
        import os

        os.environ["NZW_BROWSER_HEADLESS"] = "false"
        os.environ["NZW_LOG_LEVEL"] = "DEBUG"

        settings = Settings()

        assert not settings.browser_headless
        assert settings.log_level == "DEBUG"

        # Clean up
        del os.environ["NZW_BROWSER_HEADLESS"]
        del os.environ["NZW_LOG_LEVEL"]

    def test_get_settings(self):
        settings = get_settings()
        assert isinstance(settings, Settings)
