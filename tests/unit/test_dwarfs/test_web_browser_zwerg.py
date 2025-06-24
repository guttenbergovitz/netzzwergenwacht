"""Tests for WebBrowserZwerg."""

from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from netzzwergenwacht.dwarfs.base import Severity
from netzzwergenwacht.dwarfs.web_browser_zwerg import WebBrowserZwerg


class TestWebBrowserZwerg:
    """Test WebBrowserZwerg class."""

    def setup_method(self):
        from netzzwergenwacht.dwarfs.web_browser_zwerg import WebBrowserZwerg

        self.zwerg = WebBrowserZwerg()

    def test_initialization(self):
        """Test WebBrowserZwerg initialization."""
        zwerg = WebBrowserZwerg()
        assert zwerg.name == "Web-Browser-Zwerg"
        assert "web page analysis" in zwerg.description.lower()

    @pytest.mark.asyncio
    async def test_analyze_valid_url(self):
        """Test analysis with valid URL."""
        with patch("httpx.AsyncClient.get") as mock_get:
            mock_get.return_value.status_code = 200
            mock_get.return_value.headers = {"content-type": "text/html"}
            mock_get.return_value.content = b"<html><body>Test</body></html>"
            mock_get.return_value.url = "https://example.com"

            result = await self.zwerg.analyze("https://example.com")

            assert result.success
            assert result.url == "https://example.com"
            assert result.dwarf_name == "Web-Browser-Zwerg"

    @pytest.mark.asyncio
    async def test_analyze_invalid_url(self):
        """Test analysis with invalid URL."""
        result = await self.zwerg.analyze("invalid-url")

        assert result.success
        assert len(result.issues) == 1
        assert result.issues[0].issue_type == "invalid_url_scheme"
        assert result.issues[0].severity == Severity.HIGH

    @pytest.mark.asyncio
    @patch("netzzwergenwacht.dwarfs.web_browser_zwerg.async_playwright")
    async def test_playwright_analysis_success(self, mock_playwright):
        """Test successful Playwright analysis."""
        dwarf = WebBrowserZwerg()

        # Mock Playwright browser and page
        mock_browser = AsyncMock()
        mock_page = AsyncMock()
        mock_playwright.return_value.__aenter__.return_value.chromium.launch.return_value = mock_browser
        mock_browser.new_page.return_value = mock_page
        mock_page.goto.return_value = AsyncMock(status=200)
        mock_page.url = "https://example.com"
        mock_page.evaluate.return_value = []

        # Mock event handlers to avoid warnings
        mock_page.on = MagicMock()

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
        assert "browser_load_time_ms" in result.metadata

    @pytest.mark.asyncio
    @patch("netzzwergenwacht.dwarfs.web_browser_zwerg.async_playwright")
    async def test_playwright_analysis_with_console_errors(self, mock_playwright):
        """Test Playwright analysis with console errors."""
        dwarf = WebBrowserZwerg()

        # Mock Playwright browser and page
        mock_browser = AsyncMock()
        mock_page = AsyncMock()
        mock_playwright.return_value.__aenter__.return_value.chromium.launch.return_value = mock_browser
        mock_browser.new_page.return_value = mock_page
        mock_page.goto.return_value = AsyncMock(status=200)
        mock_page.url = "https://example.com"
        mock_page.evaluate.return_value = []

        # Mock event handlers to avoid warnings
        mock_page.on = MagicMock()

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
        assert "browser_load_time_ms" in result.metadata

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
        assert browser_failed_issues[0].severity == Severity.MEDIUM

    @pytest.mark.asyncio
    async def test_mobile_responsive_testing(self):
        """Test mobile and responsive testing functionality."""
        with patch("httpx.AsyncClient.get") as mock_get:
            mock_get.return_value.status_code = 200
            mock_get.return_value.headers = {"content-type": "text/html"}
            mock_get.return_value.content = b"<html><body>Test</body></html>"
            mock_get.return_value.url = "https://example.com"

            with patch("playwright.async_api.async_playwright") as mock_playwright:
                # Mock Playwright browser and page
                mock_browser = AsyncMock()
                mock_page = AsyncMock()
                mock_playwright.return_value.__aenter__.return_value.chromium.launch.return_value = mock_browser
                mock_browser.new_page.return_value = mock_page
                mock_page.goto.return_value = AsyncMock(status=200)
                mock_page.url = "https://example.com"

                # Mock viewport testing results
                mock_page.evaluate.side_effect = [
                    True,  # has_horizontal_scroll
                    [
                        {"tag": "BUTTON", "text": "Small button", "size": "20x20"}
                    ],  # small_touch_targets
                    [
                        {"tag": "SPAN", "text": "Small text", "fontSize": 12}
                    ],  # small_fonts
                    True,  # has_horizontal_scroll (tablet)
                    [],  # small_touch_targets (tablet)
                    [],  # small_fonts (tablet)
                    False,  # has_horizontal_scroll (desktop)
                    [],  # small_touch_targets (desktop)
                    [],  # small_fonts (desktop)
                ]

                result = await self.zwerg.analyze("https://example.com")

                # Check for mobile-specific issues
                mobile_issues = [i for i in result.issues if "mobile" in i.issue_type]
                assert len(mobile_issues) > 0

                # Check metadata
                assert "viewport_testing" in result.metadata
                viewport_results = result.metadata["viewport_testing"]
                assert "mobile" in viewport_results
                assert "tablet" in viewport_results
                assert "desktop" in viewport_results

    @pytest.mark.asyncio
    async def test_responsive_screenshots(self):
        """Test responsive screenshot functionality."""
        with patch("httpx.AsyncClient.get") as mock_get:
            mock_get.return_value.status_code = 200
            mock_get.return_value.headers = {"content-type": "text/html"}
            mock_get.return_value.content = b"<html><body>Test</body></html>"
            mock_get.return_value.url = "https://example.com"

            with patch("playwright.async_api.async_playwright") as mock_playwright:
                # Mock Playwright browser and page
                mock_browser = AsyncMock()
                mock_page = AsyncMock()
                mock_playwright.return_value.__aenter__.return_value.chromium.launch.return_value = mock_browser
                mock_browser.new_page.return_value = mock_page
                mock_page.goto.return_value = AsyncMock(status=200)
                mock_page.url = "https://example.com"

                # Mock viewport testing results (simplified)
                mock_page.evaluate.return_value = False

                with (
                    patch("os.path.exists", return_value=True),
                    patch("os.makedirs"),
                    patch("datetime.datetime") as mock_datetime,
                ):
                    mock_datetime.now.return_value.strftime.return_value = (
                        "20240101_120000"
                    )

                    result = await self.zwerg.analyze("https://example.com")

                    # Check screenshot metadata
                    assert "screenshots" in result.metadata
                    assert "screenshots_directory" in result.metadata
                    assert result.metadata["screenshots_directory"] == "output"

                    # Verify screenshot calls were made
                    assert mock_page.screenshot.called

    @pytest.mark.asyncio
    async def test_mobile_touch_target_detection(self):
        """Test detection of small touch targets."""
        with patch("httpx.AsyncClient.get") as mock_get:
            mock_get.return_value.status_code = 200
            mock_get.return_value.headers = {"content-type": "text/html"}
            mock_get.return_value.content = b"<html><body>Test</body></html>"
            mock_get.return_value.url = "https://example.com"

            with patch("playwright.async_api.async_playwright") as mock_playwright:
                # Mock Playwright browser and page
                mock_browser = AsyncMock()
                mock_page = AsyncMock()
                mock_playwright.return_value.__aenter__.return_value.chromium.launch.return_value = mock_browser
                mock_browser.new_page.return_value = mock_page
                mock_page.goto.return_value = AsyncMock(status=200)
                mock_page.url = "https://example.com"

                # Mock small touch targets
                small_targets = [
                    {"tag": "BUTTON", "text": "Small button", "size": "20x20"},
                    {"tag": "A", "text": "Small link", "size": "30x30"},
                ]
                mock_page.evaluate.side_effect = [
                    False,  # has_horizontal_scroll
                    small_targets,  # small_touch_targets
                    [],  # small_fonts
                    False,  # has_horizontal_scroll (tablet)
                    [],  # small_touch_targets (tablet)
                    [],  # small_fonts (tablet)
                    False,  # has_horizontal_scroll (desktop)
                    [],  # small_touch_targets (desktop)
                    [],  # small_fonts (desktop)
                ]

                result = await self.zwerg.analyze("https://example.com")

                # Check for touch target issues
                touch_target_issues = [
                    i for i in result.issues if "touch_targets" in i.issue_type
                ]
                assert len(touch_target_issues) > 0

                # Check metadata
                viewport_results = result.metadata["viewport_testing"]
                mobile_results = viewport_results["mobile"]
                assert len(mobile_results["small_touch_targets"]) == 2
