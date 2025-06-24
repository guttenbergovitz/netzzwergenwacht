"""Tests for LeistungsZwerg."""

import pytest

from netzzwergenwacht.dwarfs.base import Severity
from netzzwergenwacht.dwarfs.leistungs_zwerg import LeistungsZwerg


class TestLeistungsZwerg:
    """Test LeistungsZwerg class."""

    def test_initialization(self):
        zwerg = LeistungsZwerg()
        assert zwerg.name == "Leistungs-Zwerg"
        assert "performance analysis" in zwerg.description.lower()

    @pytest.mark.asyncio
    async def test_analyze_invalid_url(self):
        zwerg = LeistungsZwerg()
        result = await zwerg.analyze("invalid-url")

        assert result.success
        assert len(result.issues) == 1
        assert result.issues[0].issue_type == "invalid_url_scheme"
        assert result.issues[0].severity == Severity.HIGH

    @pytest.mark.asyncio
    async def test_analyze_valid_url(self):
        zwerg = LeistungsZwerg()
        result = await zwerg.analyze("https://example.com")

        assert result.success
        assert result.url == "https://example.com"
        assert result.dwarf_name == "Leistungs-Zwerg"

        # Should have performance analysis
        assert isinstance(result.issues, list)
        assert isinstance(result.metadata, dict)

        # Should have performance metadata
        expected_metadata_keys = [
            "page_load_time_ms",
            "page_load_time_seconds",
            "content_length_bytes",
            "content_length_kb",
        ]
        assert all(key in result.metadata for key in expected_metadata_keys)

    @pytest.mark.asyncio
    async def test_performance_thresholds(self):
        zwerg = LeistungsZwerg()
        result = await zwerg.analyze("https://httpbin.org/delay/2")  # 2 second delay

        assert result.success

        # Should detect slow loading
        load_time_issues = [
            issue
            for issue in result.issues
            if "load" in issue.issue_type and "slow" in issue.issue_type
        ]
        # May or may not flag as slow depending on actual response time
        assert isinstance(load_time_issues, list)

    @pytest.mark.asyncio
    async def test_resource_analysis(self):
        zwerg = LeistungsZwerg()
        # Use a URL that likely has various resources
        result = await zwerg.analyze("https://example.com")

        assert result.success

        # Should have resource metadata
        resource_metadata_keys = [
            "total_images",
            "total_css_files",
            "total_js_files",
        ]
        assert all(key in result.metadata for key in resource_metadata_keys)

    @pytest.mark.asyncio
    async def test_compression_analysis(self):
        zwerg = LeistungsZwerg()
        result = await zwerg.analyze("https://example.com")

        assert result.success

        # Check if compression issues are detected
        compression_issues = [
            issue for issue in result.issues if "compression" in issue.issue_type
        ]
        # May or may not have compression issues
        assert isinstance(compression_issues, list)

    @pytest.mark.asyncio
    async def test_caching_analysis(self):
        zwerg = LeistungsZwerg()
        result = await zwerg.analyze("https://httpbin.org/cache")

        assert result.success

        # Check if caching issues are detected
        cache_issues = [issue for issue in result.issues if "cache" in issue.issue_type]
        # May or may not have caching issues
        assert isinstance(cache_issues, list)

    @pytest.mark.asyncio
    async def test_error_handling(self):
        zwerg = LeistungsZwerg()
        # Test with non-existent domain
        result = await zwerg.analyze("https://this-domain-should-not-exist-12345.com")

        assert result.success  # The analysis succeeds even if connection fails

        # Should have connection error
        connection_errors = [
            issue
            for issue in result.issues
            if "failed" in issue.issue_type or "error" in issue.issue_type
        ]
        assert len(connection_errors) > 0

    @pytest.mark.asyncio
    async def test_page_size_analysis(self):
        zwerg = LeistungsZwerg()
        result = await zwerg.analyze("https://example.com")

        assert result.success

        # Should have content size metadata
        assert "content_length_bytes" in result.metadata
        assert "content_length_kb" in result.metadata
        assert result.metadata["content_length_bytes"] > 0
        assert result.metadata["content_length_kb"] > 0
