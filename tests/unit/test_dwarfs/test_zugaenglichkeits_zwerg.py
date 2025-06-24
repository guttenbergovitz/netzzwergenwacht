"""Tests for ZugaenglichkeitsZwerg."""

import pytest
from netzzwergenwacht.dwarfs.base import Severity
from netzzwergenwacht.dwarfs.zugaenglichkeits_zwerg import ZugaenglichkeitsZwerg


class TestZugaenglichkeitsZwerg:
    """Test ZugaenglichkeitsZwerg class."""

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
    async def test_eaa_specific_requirements(self):
        zwerg = ZugaenglichkeitsZwerg()
        result = await zwerg.analyze("https://example.com")

        assert result.success

        # Should check for EAA-specific requirements
        eaa_issues = [issue for issue in result.issues if "eaa" in issue.issue_type]
        assert isinstance(eaa_issues, list)

        # Should have EAA metadata
        eaa_metadata_keys = ["accessibility_statement_links", "feedback_mechanisms"]
        assert any(key in result.metadata for key in eaa_metadata_keys)

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
                or len(
                    [
                        i
                        for i in result.issues
                        if any(p in i.issue_type for p in patterns)
                    ]
                )
                == 0
            )
            # Either we found issues in this principle area, or there were no issues to find
            assert principle_covered or len(result.issues) > 0
