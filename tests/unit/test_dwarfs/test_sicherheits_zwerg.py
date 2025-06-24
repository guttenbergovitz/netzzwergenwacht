"""Tests for SicherheitsZwerg."""

import pytest

from netzzwergenwacht.dwarfs.base import Severity
from netzzwergenwacht.dwarfs.sicherheits_zwerg import SicherheitsZwerg


class TestSicherheitsZwerg:
    """Test SicherheitsZwerg class."""

    def test_initialization(self):
        zwerg = SicherheitsZwerg()
        assert zwerg.name == "Sicherheits-Zwerg"
        assert "security analysis" in zwerg.description.lower()

    @pytest.mark.asyncio
    async def test_analyze_invalid_url(self):
        zwerg = SicherheitsZwerg()
        result = await zwerg.analyze("invalid-url")

        assert result.success
        assert len(result.issues) == 1
        assert result.issues[0].issue_type == "invalid_url_scheme"
        assert result.issues[0].severity == Severity.HIGH

    @pytest.mark.asyncio
    async def test_analyze_https_url(self):
        zwerg = SicherheitsZwerg()
        result = await zwerg.analyze("https://example.com")

        assert result.success
        assert result.url == "https://example.com"
        assert result.dwarf_name == "Sicherheits-Zwerg"

        # Should have some security issues (missing headers likely)
        assert isinstance(result.issues, list)

        # Should have metadata about HTTPS usage
        assert "uses_https" in result.metadata
        assert result.metadata["uses_https"] is True

    @pytest.mark.asyncio
    async def test_analyze_http_url(self):
        zwerg = SicherheitsZwerg()
        result = await zwerg.analyze("http://example.com")

        assert result.success
        assert result.url == "http://example.com"

        # Should flag HTTP usage as security issue
        http_issues = [
            issue for issue in result.issues if "http" in issue.issue_type.lower()
        ]
        assert len(http_issues) > 0

        # Should have metadata about HTTPS usage
        assert "uses_https" in result.metadata
        assert result.metadata["uses_https"] is False

    @pytest.mark.asyncio
    async def test_security_headers_detection(self):
        zwerg = SicherheitsZwerg()
        result = await zwerg.analyze(
            "https://httpbin.org/response-headers?X-Frame-Options=DENY"
        )

        assert result.success

        # Should detect missing security headers
        header_issues = [
            issue
            for issue in result.issues
            if "missing" in issue.issue_type and "header" in issue.issue_type
        ]
        assert len(header_issues) > 0

        # Common missing headers
        missing_header_types = [issue.issue_type for issue in header_issues]
        expected_missing = [
            "missing_strict_transport_security_header",
            "missing_content_security_policy_header",
        ]
        assert any(expected in missing_header_types for expected in expected_missing)

    @pytest.mark.asyncio
    async def test_ssl_certificate_analysis(self):
        zwerg = SicherheitsZwerg()
        result = await zwerg.analyze("https://example.com")

        assert result.success

        # Should have SSL metadata for HTTPS URLs
        ssl_metadata_keys = ["ssl_version", "ssl_expires_in_days"]
        assert any(key in result.metadata for key in ssl_metadata_keys)

    @pytest.mark.asyncio
    async def test_error_handling(self):
        zwerg = SicherheitsZwerg()
        # Test with non-existent domain
        result = await zwerg.analyze("https://this-domain-should-not-exist-12345.com")

        assert result.success  # The analysis succeeds even if connection fails

        # Should have connection error
        connection_errors = [
            issue
            for issue in result.issues
            if "connection" in issue.issue_type or "error" in issue.issue_type
        ]
        assert len(connection_errors) > 0
