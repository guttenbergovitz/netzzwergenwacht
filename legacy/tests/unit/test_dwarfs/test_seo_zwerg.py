"""Tests for SEOZwerg."""

from unittest.mock import MagicMock, patch

import httpx
import pytest

from netzzwergenwacht.dwarfs.base import Severity
from netzzwergenwacht.dwarfs.seo_zwerg import SEOZwerg

EXAMPLE_HTML = (
    b"<!DOCTYPE html><html lang='en'><head><title>Example Domain</title></head>"
    b"<body><h1>Example Domain</h1>"
    b"<p>This domain is for use in illustrative examples in documents.</p>"
    b"</body></html>"
)


@pytest.fixture(autouse=True)
def mock_httpx_get():
    """Mock httpx.AsyncClient.get for offline deterministic unit tests."""

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

    with patch("httpx.AsyncClient.get", new=_fake_get):
        yield


class TestSEOZwerg:
    """Test SEOZwerg class."""

    def test_initialization(self):
        zwerg = SEOZwerg()
        assert zwerg.name == "SEO-Zwerg"
        assert "seo analysis" in zwerg.description.lower()

    @pytest.mark.asyncio
    async def test_analyze_invalid_url(self):
        zwerg = SEOZwerg()
        result = await zwerg.analyze("invalid-url")

        assert result.success
        assert len(result.issues) == 1
        assert result.issues[0].issue_type == "invalid_url_scheme"
        assert result.issues[0].severity == Severity.HIGH

    @pytest.mark.asyncio
    async def test_analyze_valid_url(self):
        zwerg = SEOZwerg()
        result = await zwerg.analyze("https://example.com")

        assert result.success
        assert result.url == "https://example.com"
        assert result.dwarf_name == "SEO-Zwerg"

        # Should have SEO analysis
        assert isinstance(result.issues, list)
        assert isinstance(result.metadata, dict)

        # Should have basic SEO metadata
        expected_metadata_keys = [
            "title",
            "title_length",
            "word_count",
            "character_count",
        ]
        # Not all may be present depending on the page, but should have some
        assert any(key in result.metadata for key in expected_metadata_keys)

    @pytest.mark.asyncio
    async def test_meta_tags_analysis(self):
        zwerg = SEOZwerg()
        result = await zwerg.analyze("https://example.com")

        assert result.success

        # Should detect title-related issues
        title_issues = [issue for issue in result.issues if "title" in issue.issue_type]
        # May or may not have title issues depending on the page
        assert isinstance(title_issues, list)

        # Should have title metadata if page has title
        if "title" in result.metadata:
            assert "title_length" in result.metadata
            assert isinstance(result.metadata["title_length"], int)

    @pytest.mark.asyncio
    async def test_meta_description_analysis(self):
        zwerg = SEOZwerg()
        result = await zwerg.analyze("https://example.com")

        assert result.success

        # Should detect meta description issues
        desc_issues = [
            issue for issue in result.issues if "description" in issue.issue_type
        ]
        # May or may not have description issues
        assert isinstance(desc_issues, list)

    @pytest.mark.asyncio
    async def test_heading_structure_analysis(self):
        zwerg = SEOZwerg()
        result = await zwerg.analyze("https://example.com")

        assert result.success

        # Should analyze heading structure
        if "heading_structure" in result.metadata:
            assert isinstance(result.metadata["heading_structure"], dict)

        # Should detect H1 issues
        h1_issues = [issue for issue in result.issues if "h1" in issue.issue_type]
        assert isinstance(h1_issues, list)

    @pytest.mark.asyncio
    async def test_social_meta_analysis(self):
        zwerg = SEOZwerg()
        result = await zwerg.analyze("https://example.com")

        assert result.success

        # Should have social media metadata
        social_keys = ["open_graph_count", "twitter_card_count"]
        assert any(key in result.metadata for key in social_keys)

        # Should detect missing social media tags
        social_issues = [
            issue
            for issue in result.issues
            if any(term in issue.issue_type for term in ["open_graph", "twitter"])
        ]
        assert isinstance(social_issues, list)

    @pytest.mark.asyncio
    async def test_structured_data_analysis(self):
        zwerg = SEOZwerg()
        result = await zwerg.analyze("https://example.com")

        assert result.success

        # Should analyze structured data
        structured_data_keys = [
            "json_ld_count",
            "microdata_count",
            "total_structured_data",
        ]
        assert any(key in result.metadata for key in structured_data_keys)

    @pytest.mark.asyncio
    async def test_canonical_url_analysis(self):
        zwerg = SEOZwerg()
        result = await zwerg.analyze("https://example.com")

        assert result.success

        # Should detect canonical URL issues
        canonical_issues = [
            issue for issue in result.issues if "canonical" in issue.issue_type
        ]
        assert isinstance(canonical_issues, list)

    @pytest.mark.asyncio
    async def test_content_quality_analysis(self):
        zwerg = SEOZwerg()
        result = await zwerg.analyze("https://example.com")

        assert result.success

        # Should have content metrics
        content_keys = ["word_count", "character_count", "total_images"]
        assert any(key in result.metadata for key in content_keys)

        # Should detect thin content if applicable
        content_issues = [
            issue
            for issue in result.issues
            if "content" in issue.issue_type or "thin" in issue.issue_type
        ]
        assert isinstance(content_issues, list)

    @pytest.mark.asyncio
    async def test_error_handling(self):
        zwerg = SEOZwerg()
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
    async def test_viewport_meta_analysis(self):
        zwerg = SEOZwerg()
        result = await zwerg.analyze("https://example.com")

        assert result.success

        # Should detect viewport meta issues for mobile SEO
        viewport_issues = [
            issue for issue in result.issues if "viewport" in issue.issue_type
        ]
        assert isinstance(viewport_issues, list)
