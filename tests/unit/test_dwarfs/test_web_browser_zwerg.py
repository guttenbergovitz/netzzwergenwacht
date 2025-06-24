"""Tests for WebBrowserZwerg."""

import pytest
from netzzwergenwacht.dwarfs.base import Severity
from netzzwergenwacht.dwarfs.web_browser_zwerg import WebBrowserZwerg


class TestWebBrowserZwerg:
    """Test WebBrowserZwerg class."""

    def test_initialization(self):
        dwarf = WebBrowserZwerg()
        assert dwarf.name == "Web-Browser-Zwerg"
        assert "http-based" in dwarf.description.lower()

    @pytest.mark.asyncio
    async def test_analyze_valid_url(self):
        dwarf = WebBrowserZwerg()
        result = await dwarf.analyze("https://example.com")

        assert result.success
        assert result.url == "https://example.com"
        assert result.dwarf_name == "Web-Browser-Zwerg"
        # Note: example.com may have some SEO/accessibility issues
        assert isinstance(result.issues, list)

    @pytest.mark.asyncio
    async def test_analyze_invalid_url(self):
        dwarf = WebBrowserZwerg()
        result = await dwarf.analyze("invalid-url")

        assert result.success
        assert len(result.issues) == 1
        assert result.issues[0].issue_type == "invalid_url_scheme"
        assert result.issues[0].severity == Severity.HIGH
