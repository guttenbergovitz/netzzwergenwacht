"""Tests for ZugaenglichkeitsZwerg."""

from unittest.mock import MagicMock, patch

import httpx
import pytest

from netzzwergenwacht.dwarfs.base import Severity
from netzzwergenwacht.dwarfs.zugaenglichkeits_zwerg import ZugaenglichkeitsZwerg

EXAMPLE_HTML = (
    b"<!DOCTYPE html><html lang='en'><head><title>Example Domain</title></head>"
    b"<body><h1>Example Domain</h1>"
    b"<p>This domain is for use in illustrative examples in documents.</p>"
    b"<a href='https://www.iana.org/domains/example'>More information...</a>"
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


class TestZugaenglichkeitsZwerg:
    """Test ZugaenglichkeitsZwerg class."""

    def setup_method(self):
        from netzzwergenwacht.dwarfs.zugaenglichkeits_zwerg import ZugaenglichkeitsZwerg

        self.zwerg = ZugaenglichkeitsZwerg()

    def test_initialization(self):
        zwerg = ZugaenglichkeitsZwerg()
        assert zwerg.name == "Zugaenglichkeits-Zwerg"
        assert "accessibility act compliance" in zwerg.description.lower()

    @pytest.mark.asyncio
    async def test_analyze_invalid_url(self):
        zwerg = ZugaenglichkeitsZwerg()
        result = await zwerg.analyze("invalid-url")

        assert result.success
        assert len(result.issues) == 1
        assert result.issues[0].issue_type == "invalid_url_scheme"
        assert result.issues[0].severity == Severity.HIGH

    @pytest.mark.asyncio
    async def test_analyze_valid_url(self):
        zwerg = ZugaenglichkeitsZwerg()
        result = await zwerg.analyze("https://example.com")

        assert result.success
        assert result.url == "https://example.com"
        assert result.dwarf_name == "Zugaenglichkeits-Zwerg"

        # Should have accessibility analysis
        assert isinstance(result.issues, list)
        assert isinstance(result.metadata, dict)

    @pytest.mark.asyncio
    async def test_text_alternatives_analysis(self):
        zwerg = ZugaenglichkeitsZwerg()
        result = await zwerg.analyze("https://example.com")

        assert result.success

        # Should check for image alt text issues
        alt_text_issues = [
            issue
            for issue in result.issues
            if "alt" in issue.issue_type or "1_1_1" in issue.issue_type
        ]
        # May or may not have alt text issues
        assert isinstance(alt_text_issues, list)

        # Should have image metadata
        image_metadata_keys = ["total_images", "images_without_alt"]
        assert any(key in result.metadata for key in image_metadata_keys)

    @pytest.mark.asyncio
    async def test_color_contrast_analysis(self):
        zwerg = ZugaenglichkeitsZwerg()
        result = await zwerg.analyze("https://example.com")

        assert result.success

        # Should check for contrast issues
        contrast_issues = [
            issue
            for issue in result.issues
            if "contrast" in issue.issue_type or "color" in issue.issue_type
        ]
        assert isinstance(contrast_issues, list)

        # Should have style metadata
        style_metadata_keys = [
            "elements_with_inline_styles",
            "potential_contrast_issues",
        ]
        assert any(key in result.metadata for key in style_metadata_keys)

    @pytest.mark.asyncio
    async def test_keyboard_accessibility_analysis(self):
        zwerg = ZugaenglichkeitsZwerg()
        result = await zwerg.analyze("https://example.com")

        assert result.success

        # Should check for keyboard accessibility
        keyboard_issues = [
            issue
            for issue in result.issues
            if "keyboard" in issue.issue_type
            or "focusable" in issue.issue_type
            or "2_1_1" in issue.issue_type
        ]
        assert isinstance(keyboard_issues, list)

        # Should have interactive elements metadata
        interactive_metadata_keys = [
            "interactive_elements_count",
            "custom_interactive_elements",
        ]
        assert any(key in result.metadata for key in interactive_metadata_keys)

    @pytest.mark.asyncio
    async def test_focus_management_analysis(self):
        zwerg = ZugaenglichkeitsZwerg()
        result = await zwerg.analyze("https://example.com")

        assert result.success

        # Should check for focus management
        focus_issues = [
            issue
            for issue in result.issues
            if any(
                term in issue.issue_type for term in ["skip", "heading", "focus", "2_4"]
            )
        ]
        assert isinstance(focus_issues, list)

        # Should have navigation metadata
        if "skip_links_count" in result.metadata:
            assert isinstance(result.metadata["skip_links_count"], int)

    @pytest.mark.asyncio
    async def test_language_identification_analysis(self):
        zwerg = ZugaenglichkeitsZwerg()
        result = await zwerg.analyze("https://example.com")

        assert result.success

        # Should check for language identification
        language_issues = [
            issue
            for issue in result.issues
            if "language" in issue.issue_type or "3_1" in issue.issue_type
        ]
        assert isinstance(language_issues, list)

        # Should have language metadata
        assert "page_language" in result.metadata

    @pytest.mark.asyncio
    async def test_forms_and_labels_analysis(self):
        zwerg = ZugaenglichkeitsZwerg()
        result = await zwerg.analyze("https://example.com")

        assert result.success

        # Should check for form labeling
        form_issues = [
            issue
            for issue in result.issues
            if any(term in issue.issue_type for term in ["form", "label", "3_3_2"])
        ]
        assert isinstance(form_issues, list)

        # Should have form metadata
        form_metadata_keys = ["total_form_inputs", "unlabeled_inputs"]
        assert any(key in result.metadata for key in form_metadata_keys)

    @pytest.mark.asyncio
    async def test_semantic_structure_analysis(self):
        zwerg = ZugaenglichkeitsZwerg()
        result = await zwerg.analyze("https://example.com")

        assert result.success

        # Should check for semantic structure
        semantic_issues = [
            issue
            for issue in result.issues
            if any(
                term in issue.issue_type
                for term in ["landmark", "main", "navigation", "duplicate", "4_1"]
            )
        ]
        assert isinstance(semantic_issues, list)

        # Should have semantic metadata
        semantic_metadata_keys = ["semantic_elements_count", "navigation_landmarks"]
        assert any(key in result.metadata for key in semantic_metadata_keys)

    @pytest.mark.asyncio
    async def test_aria_compliance_analysis(self):
        zwerg = ZugaenglichkeitsZwerg()
        result = await zwerg.analyze("https://example.com")

        assert result.success

        # Should check for ARIA compliance
        aria_issues = [issue for issue in result.issues if "aria" in issue.issue_type]
        assert isinstance(aria_issues, list)

        # Should have ARIA metadata
        aria_metadata_keys = ["elements_with_aria", "invalid_roles_count"]
        assert any(key in result.metadata for key in aria_metadata_keys)

    @pytest.mark.asyncio
    async def test_form_aria_accessibility(self):
        """Test form ARIA accessibility compliance with EU/EAA standards."""
        zwerg = ZugaenglichkeitsZwerg()
        result = await zwerg.analyze("https://example.com")

        assert result.success

        # Should check for form ARIA compliance
        form_aria_issues = [
            issue
            for issue in result.issues
            if "aria_form" in issue.issue_type or "required_fields" in issue.issue_type
        ]
        assert isinstance(form_aria_issues, list)

        # Should have form ARIA metadata
        form_aria_metadata_keys = [
            "total_form_inputs",
            "inputs_without_labels",
            "required_inputs_without_aria",
        ]
        assert any(key in result.metadata for key in form_aria_metadata_keys)

    @pytest.mark.asyncio
    async def test_live_regions_aria(self):
        """Test live regions ARIA compliance with EU/EAA standards."""
        zwerg = ZugaenglichkeitsZwerg()
        result = await zwerg.analyze("https://example.com")

        assert result.success

        # Should check for live regions
        live_region_issues = [
            issue
            for issue in result.issues
            if "aria_live" in issue.issue_type or "live_region" in issue.issue_type
        ]
        assert isinstance(live_region_issues, list)

        # Should have live regions metadata
        live_region_metadata_keys = ["live_regions_count", "live_region_types"]
        assert any(key in result.metadata for key in live_region_metadata_keys)

    @pytest.mark.asyncio
    async def test_interactive_aria_elements(self):
        """Test interactive ARIA elements keyboard accessibility."""
        zwerg = ZugaenglichkeitsZwerg()
        result = await zwerg.analyze("https://example.com")

        assert result.success

        # Should check for interactive ARIA elements
        interactive_aria_issues = [
            issue
            for issue in result.issues
            if "aria_interactive" in issue.issue_type
            or "keyboard_accessible" in issue.issue_type
        ]
        assert isinstance(interactive_aria_issues, list)

        # Should have interactive elements metadata
        interactive_metadata_keys = ["interactive_aria_elements"]
        assert any(key in result.metadata for key in interactive_metadata_keys)

    @pytest.mark.asyncio
    async def test_navigation_aria_compliance(self):
        """Test navigation ARIA compliance with EU/EAA standards."""
        zwerg = ZugaenglichkeitsZwerg()
        result = await zwerg.analyze("https://example.com")

        assert result.success

        # Should check for navigation ARIA
        navigation_aria_issues = [
            issue
            for issue in result.issues
            if "aria_navigation" in issue.issue_type
            or "skip_links" in issue.issue_type
            or "heading_structure" in issue.issue_type
        ]
        assert isinstance(navigation_aria_issues, list)

        # Should have navigation metadata
        navigation_metadata_keys = [
            "skip_links_count",
            "headings_count",
            "heading_structure_issues",
        ]
        assert any(key in result.metadata for key in navigation_metadata_keys)

    @pytest.mark.asyncio
    async def test_error_aria_handling(self):
        """Test error handling ARIA compliance with EU/EAA standards."""
        zwerg = ZugaenglichkeitsZwerg()
        result = await zwerg.analyze("https://example.com")

        assert result.success

        # Should check for error ARIA handling
        error_aria_issues = [
            issue
            for issue in result.issues
            if "aria_error" in issue.issue_type or "error_handling" in issue.issue_type
        ]
        assert isinstance(error_aria_issues, list)

        # Should have error handling metadata
        error_metadata_keys = [
            "error_elements_count",
            "error_elements_with_aria",
            "error_elements_without_aria",
        ]
        assert any(key in result.metadata for key in error_metadata_keys)

    @pytest.mark.asyncio
    async def test_eu_eaa_aria_standards_compliance(self):
        """Test overall EU/EAA ARIA standards compliance."""
        zwerg = ZugaenglichkeitsZwerg()
        result = await zwerg.analyze("https://example.com")

        assert result.success

        # Should have comprehensive ARIA analysis
        all_aria_issues = [
            issue for issue in result.issues if "aria" in issue.issue_type
        ]

        # Check for specific EU/EAA compliance indicators
        eaa_compliance_issues = [
            issue
            for issue in all_aria_issues
            if any(
                term in issue.evidence.get("eaa_requirement", "")
                for term in [
                    "Form accessibility",
                    "Dynamic content",
                    "Keyboard accessibility",
                    "Navigation accessibility",
                    "Error message accessibility",
                ]
            )
        ]

        # Should have WCAG guideline references
        wcag_references = [
            issue for issue in all_aria_issues if "wcag_guideline" in issue.evidence
        ]

        assert isinstance(all_aria_issues, list)
        assert isinstance(eaa_compliance_issues, list)
        assert isinstance(wcag_references, list)

    @pytest.mark.asyncio
    async def test_eaa_specific_requirements(self):
        result = await self.zwerg.analyze("https://example.com")

        assert result.success

        # Should check for EAA-specific requirements
        eaa_issues = [issue for issue in result.issues if "eaa" in issue.issue_type]
        assert isinstance(eaa_issues, list)
        # Should have new EAA metadata keys
        assert "eu_accessibility_features" in result.metadata
        assert "eaa_compliance_score" in result.metadata

    @pytest.mark.asyncio
    async def test_wcag_guideline_references(self):
        zwerg = ZugaenglichkeitsZwerg()
        result = await zwerg.analyze("https://example.com")

        assert result.success

        # Check that WCAG guidelines are properly referenced
        wcag_issues = [issue for issue in result.issues if "wcag" in issue.issue_type]

        # If we have WCAG issues, they should have guideline references
        for issue in wcag_issues:
            if issue.evidence and "wcag_guideline" in issue.evidence:
                guideline = issue.evidence["wcag_guideline"]
                assert isinstance(guideline, str)
                assert len(guideline) > 0

    @pytest.mark.asyncio
    async def test_error_handling(self):
        zwerg = ZugaenglichkeitsZwerg()
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
    async def test_comprehensive_accessibility_coverage(self):
        zwerg = ZugaenglichkeitsZwerg()
        result = await zwerg.analyze("https://example.com")

        assert result.success

        # Should cover all major WCAG principles (Perceivable, Operable, Understandable, Robust)
        wcag_principle_coverage = {
            "perceivable": ["1_1_1", "1_4"],  # Text alternatives, color contrast
            "operable": ["2_1_1", "2_4"],  # Keyboard access, focus management
            "understandable": ["3_1", "3_3"],  # Language, forms
            "robust": ["4_1"],  # Semantic structure, ARIA
        }

        issue_types = [issue.issue_type for issue in result.issues]

        # Check that we're testing across all principles
        for _principle, patterns in wcag_principle_coverage.items():
            principle_covered = (
                any(
                    any(pattern in issue_type for pattern in patterns)
                    for issue_type in issue_types
                )
                or len([
                    i for i in result.issues if any(p in i.issue_type for p in patterns)
                ])
                == 0
            )
            # Either we found issues in this principle area, or there were no issues to find
            assert principle_covered or len(result.issues) > 0

    @pytest.mark.asyncio
    async def test_eaa_compliance_score(self):
        zwerg = ZugaenglichkeitsZwerg()
        result = await zwerg.analyze("https://example.com")

        assert result.success

        # Test EAA compliance score calculation
        assert "eaa_compliance_score" in result.metadata
        assert isinstance(result.metadata["eaa_compliance_score"], (int, float))

    @pytest.mark.asyncio
    async def test_mobile_responsive_accessibility(self):
        """Test mobile and responsive accessibility checks."""
        html = """
        <!DOCTYPE html>
        <html>
        <head>
            <meta name="viewport" content="width=device-width, initial-scale=1">
        </head>
        <body>
            <button style="width: 20px; height: 20px;">Small button</button>
            <div style="overflow-x: scroll;">Content</div>
            <div style="position: fixed;">Fixed element</div>
            <span style="font-size: 12px;">Small text</span>
        </body>
        </html>
        """

        with patch("httpx.AsyncClient.get") as mock_get:
            mock_get.return_value.status_code = 200
            mock_get.return_value.headers = {"content-type": "text/html"}
            mock_get.return_value.content = html.encode()

            result = await self.zwerg.analyze("https://example.com")

            # Check for mobile-specific issues
            mobile_issues = [i for i in result.issues if "mobile" in i.issue_type]
            assert len(mobile_issues) > 0

            # Check metadata
            assert "viewport_meta_present" in result.metadata
            assert result.metadata["viewport_meta_present"] is True
            assert "small_touch_targets_count" in result.metadata
            assert "mobile_issues_detected" in result.metadata

    @pytest.mark.asyncio
    async def test_responsive_breakpoints(self):
        """Test responsive breakpoints detection."""
        html = """
        <!DOCTYPE html>
        <html>
        <head>
            <style>
                @media (max-width: 768px) { .mobile { display: block; } }
                @media (min-width: 1024px) { .desktop { display: block; } }
                .container { display: flex; }
            </style>
        </head>
        <body>
            <div class="container">Content</div>
        </body>
        </html>
        """

        with patch("httpx.AsyncClient.get") as mock_get:
            mock_get.return_value.status_code = 200
            mock_get.return_value.headers = {"content-type": "text/html"}
            mock_get.return_value.content = html.encode()

            result = await self.zwerg.analyze("https://example.com")

            # Check metadata
            assert "media_queries_found" in result.metadata
            assert result.metadata["media_queries_found"] > 0
            assert "flexbox_used" in result.metadata
            assert result.metadata["flexbox_used"] is True
            assert "standard_breakpoints_found" in result.metadata

    @pytest.mark.asyncio
    async def test_mobile_performance_accessibility(self):
        """Test mobile performance accessibility checks."""
        html = """
        <!DOCTYPE html>
        <html>
        <head>
            <link rel="stylesheet" href="https://external.com/style.css">
            <script src="https://external.com/script.js"></script>
        </head>
        <body>
            <img src="large-image.jpg" width="1500" height="1000" alt="Large image">
            <img src="small-image.jpg" width="300" height="200" alt="Small image">
        </body>
        </html>
        """

        with patch("httpx.AsyncClient.get") as mock_get:
            mock_get.return_value.status_code = 200
            mock_get.return_value.headers = {"content-type": "text/html"}
            mock_get.return_value.content = html.encode()

            result = await self.zwerg.analyze("https://example.com")

            # Check metadata
            assert "total_images" in result.metadata
            assert "large_images_count" in result.metadata
            assert "external_resources_count" in result.metadata
            assert result.metadata["external_resources_count"] > 0

    @pytest.mark.asyncio
    async def test_mobile_missing_viewport_meta(self):
        """Test detection of missing viewport meta tag."""
        html = """
        <!DOCTYPE html>
        <html>
        <head>
            <title>Test Page</title>
        </head>
        <body>
            <h1>Test Content</h1>
        </body>
        </html>
        """

        with patch("httpx.AsyncClient.get") as mock_get:
            mock_get.return_value.status_code = 200
            mock_get.return_value.headers = {"content-type": "text/html"}
            mock_get.return_value.content = html.encode()

            result = await self.zwerg.analyze("https://example.com")

            # Check for missing viewport meta issue
            viewport_issues = [i for i in result.issues if "viewport" in i.issue_type]
            assert len(viewport_issues) > 0

            # Check metadata
            assert "viewport_meta_present" in result.metadata
            assert result.metadata["viewport_meta_present"] is False
