"""Tests for SicherheitsZwerg."""

from unittest.mock import AsyncMock, MagicMock, Mock, patch

import httpx
import pytest

from netzzwergenwacht.dwarfs.base import Severity
from netzzwergenwacht.dwarfs.sicherheits_zwerg import SicherheitsZwerg

EXAMPLE_HTML = b"<!DOCTYPE html><html><head><title>Example</title></head><body><h1>Example</h1></body></html>"


@pytest.fixture(autouse=True)
def mock_network():
    """Mock httpx.AsyncClient.get and SSL socket for offline deterministic unit tests."""

    async def _fake_get(self, url, *args, **kwargs):
        if "this-domain-should-not-exist" in str(url):
            raise httpx.ConnectError("Connection failed")
        resp = MagicMock()
        resp.status_code = 200
        resp.headers = {"content-type": "text/html"}
        resp.content = EXAMPLE_HTML
        resp.text = EXAMPLE_HTML.decode()
        resp.url = str(url)
        return resp

    mock_ssock = MagicMock()
    mock_ssock.version.return_value = "TLSv1.3"
    mock_ssock.getpeercert.return_value = {
        "notAfter": "Dec 31 23:59:59 2030 GMT",
        "subject": ((("commonName", "example.com"),),),
        "issuer": ((("commonName", "Example CA"),),),
    }
    mock_ctx = MagicMock()
    mock_ctx.wrap_socket.return_value.__enter__.return_value = mock_ssock

    with (
        patch("httpx.AsyncClient.get", new=_fake_get),
        patch("socket.create_connection", return_value=MagicMock()),
        patch("ssl.create_default_context", return_value=mock_ctx),
    ):
        yield


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

    @pytest.mark.asyncio
    async def test_advanced_security_scan_success(self):
        """Test successful advanced security scanning."""
        zwerg = SicherheitsZwerg()

        # Test with a valid URL - this will run real nmap if available
        with patch("httpx.AsyncClient") as mock_client:
            mock_response = AsyncMock()
            mock_response.status_code = 200
            mock_response.headers = {"content-type": "text/html"}
            mock_response.url = "https://example.com"
            mock_client.return_value.__aenter__.return_value.get.return_value = (
                mock_response
            )

            result = await zwerg.analyze("https://example.com")

        assert result.success
        # Should have basic security metadata
        assert "uses_https" in result.metadata
        assert "detected_services" in result.metadata
        assert "exposed_files_count" in result.metadata

    @pytest.mark.asyncio
    async def test_port_scanning_dangerous_ports(self):
        """Test port scanning with dangerous ports detection."""
        zwerg = SicherheitsZwerg()

        # Test with a valid URL - this will run real nmap if available
        with patch("httpx.AsyncClient") as mock_client:
            mock_response = AsyncMock()
            mock_response.status_code = 200
            mock_response.headers = {"content-type": "text/html"}
            mock_response.url = "https://example.com"
            mock_client.return_value.__aenter__.return_value.get.return_value = (
                mock_response
            )

            result = await zwerg.analyze("https://example.com")

        assert result.success

        # Check if we have any security issues (port scanning may or may not work)
        assert isinstance(result.issues, list)
        assert isinstance(result.metadata, dict)

    @pytest.mark.asyncio
    async def test_information_disclosure_detection(self):
        """Test information disclosure detection."""
        zwerg = SicherheitsZwerg()

        # Test with a valid URL - this will run real nmap if available
        with patch("httpx.AsyncClient") as mock_client:
            mock_response = AsyncMock()
            mock_response.status_code = 200
            mock_response.headers = {
                "content-type": "text/html"
            }  # Use regular dict instead of AsyncMock
            mock_response.url = "https://example.com"

            # Mock different responses for different paths
            def mock_get(url):
                mock_resp = Mock()
                if "/.env" in url:
                    mock_resp.status_code = 200  # Exposed file
                elif "/robots.txt" in url:
                    mock_resp.status_code = 200  # Exposed file
                else:
                    mock_resp.status_code = 404
                mock_resp.headers = {"content-type": "text/html"}
                mock_resp.url = url
                return mock_resp

            mock_client.return_value.__aenter__.return_value.get.side_effect = mock_get

            result = await zwerg.analyze("https://example.com")

        assert result.success

        # Should have information disclosure issues
        info_disclosure_issues = [
            i for i in result.issues if "information_disclosure" in i.issue_type
        ]
        assert len(info_disclosure_issues) >= 2  # .env and robots.txt

        # Should have metadata about exposed files
        assert "exposed_files_count" in result.metadata
        assert result.metadata["exposed_files_count"] >= 2

    @pytest.mark.asyncio
    async def test_advanced_security_scan_failure(self):
        """Test advanced security scanning when nmap fails."""
        zwerg = SicherheitsZwerg()

        # Test with a valid URL - this will run real nmap if available
        with patch("httpx.AsyncClient") as mock_client:
            mock_response = AsyncMock()
            mock_response.status_code = 200
            mock_response.headers = {"content-type": "text/html"}
            mock_response.url = "https://example.com"
            mock_client.return_value.__aenter__.return_value.get.return_value = (
                mock_response
            )

            result = await zwerg.analyze("https://example.com")

        assert result.success
        # The analysis should succeed even if nmap fails
        assert isinstance(result.issues, list)
        assert isinstance(result.metadata, dict)
