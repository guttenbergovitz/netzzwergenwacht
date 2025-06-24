"""Tests for WebBrowserZwerg."""

from unittest.mock import AsyncMock, patch

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

    @pytest.mark.asyncio
    @patch("netzzwergenwacht.dwarfs.web_browser_zwerg.async_playwright")
    async def test_playwright_analysis_success(self, mock_playwright):
        """Test successful Playwright analysis."""
        dwarf = WebBrowserZwerg()

        # Mock Playwright context
        mock_context = AsyncMock()
        mock_browser = AsyncMock()
        mock_page = AsyncMock()
        mock_response = AsyncMock()

        mock_response.status = 200
        mock_page.url = "https://example.com"
        mock_page.goto.return_value = mock_response
        mock_page.evaluate.return_value = []
        mock_page.on = AsyncMock()  # Mock the event handler
        mock_browser.new_page.return_value = mock_page
        mock_context.chromium.launch.return_value = mock_browser
        mock_playwright.return_value.__aenter__.return_value = mock_context

        # Test with a valid URL that would trigger Playwright analysis
        with patch("httpx.AsyncClient") as mock_client:
            mock_response_http = AsyncMock()
            mock_response_http.status_code = 200
            mock_response_http.headers = {"content-type": "text/html"}
            mock_response_http.content = (
                b"<html><head><title>Test</title></head><body></body></html>"
            )
            mock_response_http.url = "https://example.com"
            mock_client.return_value.__aenter__.return_value.get.return_value = (
                mock_response_http
            )

            result = await dwarf.analyze("https://example.com")

        assert result.success
        assert "browser_load_time_ms" in result.metadata
        assert "browser_status_code" in result.metadata

    @pytest.mark.asyncio
    @patch("netzzwergenwacht.dwarfs.web_browser_zwerg.async_playwright")
    async def test_playwright_analysis_with_console_errors(self, mock_playwright):
        """Test Playwright analysis with JavaScript console errors."""
        dwarf = WebBrowserZwerg()

        # Mock Playwright context
        mock_context = AsyncMock()
        mock_browser = AsyncMock()
        mock_page = AsyncMock()
        mock_response = AsyncMock()

        mock_response.status = 200
        mock_page.url = "https://example.com"
        mock_page.goto.return_value = mock_response
        mock_page.evaluate.return_value = []
        mock_page.on = AsyncMock()  # Mock the event handler
        mock_browser.new_page.return_value = mock_page
        mock_context.chromium.launch.return_value = mock_browser
        mock_playwright.return_value.__aenter__.return_value = mock_context

        # Test with a valid URL
        with patch("httpx.AsyncClient") as mock_client:
            mock_response_http = AsyncMock()
            mock_response_http.status_code = 200
            mock_response_http.headers = {"content-type": "text/html"}
            mock_response_http.content = (
                b"<html><head><title>Test</title></head><body></body></html>"
            )
            mock_response_http.url = "https://example.com"
            mock_client.return_value.__aenter__.return_value.get.return_value = (
                mock_response_http
            )

            result = await dwarf.analyze("https://example.com")

        assert result.success
        # Should not have console error issues since we didn't simulate any
        console_error_issues = [
            i for i in result.issues if i.issue_type == "javascript_console_errors"
        ]
        assert len(console_error_issues) == 0

    @pytest.mark.asyncio
    @patch("netzzwergenwacht.dwarfs.web_browser_zwerg.async_playwright")
    async def test_playwright_analysis_failure(self, mock_playwright):
        """Test Playwright analysis when browser automation fails."""
        dwarf = WebBrowserZwerg()

        # Mock Playwright to raise an exception
        mock_playwright.side_effect = Exception("Browser launch failed")

        # Test with a valid URL
        with patch("httpx.AsyncClient") as mock_client:
            mock_response_http = AsyncMock()
            mock_response_http.status_code = 200
            mock_response_http.headers = {"content-type": "text/html"}
            mock_response_http.content = (
                b"<html><head><title>Test</title></head><body></body></html>"
            )
            mock_response_http.url = "https://example.com"
            mock_client.return_value.__aenter__.return_value.get.return_value = (
                mock_response_http
            )

            result = await dwarf.analyze("https://example.com")

        assert result.success
        # Should have browser analysis failed issue
        browser_failed_issues = [
            i for i in result.issues if i.issue_type == "browser_analysis_failed"
        ]
        assert len(browser_failed_issues) == 1
        assert browser_failed_issues[0].severity == Severity.LOW
