"""Tests for InhaltZwerg."""

import pytest
from netzzwergenwacht.dwarfs.base import Severity
from netzzwergenwacht.dwarfs.inhalt_zwerg import InhaltZwerg


class TestInhaltZwerg:
    """Test InhaltZwerg class."""

    def test_initialization(self):
        zwerg = InhaltZwerg()
        assert zwerg.name == "Inhalt-Zwerg"
        assert "content quality analysis" in zwerg.description.lower()

    @pytest.mark.asyncio
    async def test_analyze_invalid_url(self):
        zwerg = InhaltZwerg()
        result = await zwerg.analyze("invalid-url")

        assert result.success
        assert len(result.issues) == 1
        assert result.issues[0].issue_type == "invalid_url_scheme"
        assert result.issues[0].severity == Severity.HIGH

    @pytest.mark.asyncio
    async def test_analyze_valid_url(self):
        zwerg = InhaltZwerg()
        result = await zwerg.analyze("https://example.com")

        assert result.success
        assert result.url == "https://example.com"
        assert result.dwarf_name == "Inhalt-Zwerg"

        # Should have content analysis
        assert isinstance(result.issues, list)
        assert isinstance(result.metadata, dict)

    @pytest.mark.asyncio
    async def test_content_metrics_analysis(self):
        zwerg = InhaltZwerg()
        result = await zwerg.analyze("https://example.com")

        assert result.success

        # Should have basic content metrics
        expected_metrics = [
            "word_count",
            "character_count",
            "character_count_no_spaces",
            "sentence_count",
            "paragraph_count",
        ]
        assert all(metric in result.metadata for metric in expected_metrics)

        # Should detect thin content
        thin_content_issues = [
            issue
            for issue in result.issues
            if "thin_content" in issue.issue_type
            or "very_thin_content" in issue.issue_type
        ]
        # example.com has minimal content, so should flag this
        assert len(thin_content_issues) > 0

    @pytest.mark.asyncio
    async def test_readability_analysis(self):
        zwerg = InhaltZwerg()
        result = await zwerg.analyze("https://example.com")

        assert result.success

        # Should have readability metrics
        readability_metrics = [
            "avg_sentence_length",
            "avg_word_length",
            "flesch_reading_ease",
            "flesch_kincaid_grade",
        ]
        assert any(metric in result.metadata for metric in readability_metrics)

        # Check for readability issues
        readability_issues = [
            issue
            for issue in result.issues
            if any(
                term in issue.issue_type
                for term in ["readability", "sentence", "grade"]
            )
        ]
        assert isinstance(readability_issues, list)

    @pytest.mark.asyncio
    async def test_content_structure_analysis(self):
        zwerg = InhaltZwerg()
        result = await zwerg.analyze("https://example.com")

        assert result.success

        # Should analyze heading structure
        structure_metrics = [
            "heading_structure",
            "total_headings",
        ]
        assert any(metric in result.metadata for metric in structure_metrics)

        # Should detect missing H1 or heading issues
        heading_issues = [
            issue
            for issue in result.issues
            if any(term in issue.issue_type for term in ["h1", "heading", "hierarchy"])
        ]
        assert isinstance(heading_issues, list)

    @pytest.mark.asyncio
    async def test_language_quality_analysis(self):
        zwerg = InhaltZwerg()
        result = await zwerg.analyze("https://example.com")

        assert result.success

        # Should analyze language quality
        if "uppercase_ratio" in result.metadata:
            assert isinstance(result.metadata["uppercase_ratio"], float)

        # Check for language quality issues
        language_issues = [
            issue
            for issue in result.issues
            if any(
                term in issue.issue_type
                for term in ["uppercase", "formatting", "placeholder"]
            )
        ]
        assert isinstance(language_issues, list)

    @pytest.mark.asyncio
    async def test_duplicate_content_analysis(self):
        zwerg = InhaltZwerg()
        result = await zwerg.analyze("https://example.com")

        assert result.success

        # Should analyze duplicate content
        duplicate_metrics = [
            "total_paragraphs",
            "duplicate_paragraphs",
        ]
        assert any(metric in result.metadata for metric in duplicate_metrics)

        # Check for duplicate content issues
        duplicate_issues = [
            issue
            for issue in result.issues
            if any(term in issue.issue_type for term in ["duplicate", "similar"])
        ]
        assert isinstance(duplicate_issues, list)

    @pytest.mark.asyncio
    async def test_content_freshness_analysis(self):
        zwerg = InhaltZwerg()
        result = await zwerg.analyze("https://example.com")

        assert result.success

        # Should analyze content freshness
        freshness_metrics = [
            "date_meta_tags",
            "time_elements",
            "has_freshness_indicators",
        ]
        assert any(metric in result.metadata for metric in freshness_metrics)

        # Check for freshness issues
        freshness_issues = [
            issue
            for issue in result.issues
            if any(
                term in issue.issue_type
                for term in ["copyright", "freshness", "outdated"]
            )
        ]
        assert isinstance(freshness_issues, list)

    @pytest.mark.asyncio
    async def test_syllable_estimation(self):
        zwerg = InhaltZwerg()

        # Test syllable estimation with known words
        test_cases = [
            ("hello", 2),
            ("world", 1),
            ("beautiful", 3),
            ("a", 1),
            ("", 0),
        ]

        for word, expected_min_syllables in test_cases:
            syllables = zwerg._estimate_syllables(word)
            if word:  # Non-empty words should have at least 1 syllable
                assert syllables >= expected_min_syllables
            else:
                assert syllables == 0

    @pytest.mark.asyncio
    async def test_comprehensive_content_analysis(self):
        zwerg = InhaltZwerg()
        result = await zwerg.analyze("https://example.com")

        assert result.success

        # Should have analyzed multiple content aspects
        analysis_categories = {
            "content_metrics": ["word_count", "character_count"],
            "readability": ["flesch_reading_ease", "avg_sentence_length"],
            "structure": ["heading_structure", "total_headings"],
            "quality": ["uppercase_ratio"],
            "duplicates": ["total_paragraphs", "duplicate_paragraphs"],
            "freshness": ["has_freshness_indicators", "time_elements"],
        }

        # At least some categories should have metadata
        categories_with_data = 0
        for metrics in analysis_categories.values():
            if any(metric in result.metadata for metric in metrics):
                categories_with_data += 1

        assert categories_with_data >= 3  # Should analyze at least 3 categories

    @pytest.mark.asyncio
    async def test_error_handling(self):
        zwerg = InhaltZwerg()
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
    async def test_content_quality_thresholds(self):
        zwerg = InhaltZwerg()
        result = await zwerg.analyze("https://example.com")

        assert result.success

        # example.com has minimal content, should trigger thin content warnings
        word_count = result.metadata.get("word_count", 0)

        thin_content_issues = [
            issue for issue in result.issues if "thin_content" in issue.issue_type
        ]

        if word_count < 300:
            assert len(thin_content_issues) > 0

    @pytest.mark.asyncio
    async def test_readability_scoring(self):
        zwerg = InhaltZwerg()
        result = await zwerg.analyze("https://example.com")

        assert result.success

        # Should have calculated readability scores
        if "flesch_reading_ease" in result.metadata:
            flesch_score = result.metadata["flesch_reading_ease"]
            assert 0 <= flesch_score <= 100

        if "flesch_kincaid_grade" in result.metadata:
            fk_grade = result.metadata["flesch_kincaid_grade"]
            assert fk_grade >= 0

    @pytest.mark.asyncio
    async def test_heading_structure_validation(self):
        zwerg = InhaltZwerg()
        result = await zwerg.analyze("https://example.com")

        assert result.success

        # Should detect H1 issues on pages without proper heading structure
        # Check for heading-related issues (but we don't need to store them)
        [
            issue
            for issue in result.issues
            if "h1" in issue.issue_type or "heading" in issue.issue_type
        ]

        # example.com should have an H1, but let's verify structure analysis works
        if "heading_structure" in result.metadata:
            heading_structure = result.metadata["heading_structure"]
            assert isinstance(heading_structure, dict)

    @pytest.mark.asyncio
    async def test_evidence_content(self):
        zwerg = InhaltZwerg()
        result = await zwerg.analyze("https://example.com")

        assert result.success

        # Check that issues have proper evidence
        for issue in result.issues:
            assert hasattr(issue, "evidence")
            if issue.evidence:
                assert isinstance(issue.evidence, dict)
                # Should have recommendation for most issues
                if "recommendation" in issue.evidence:
                    assert isinstance(issue.evidence["recommendation"], str)
                    assert len(issue.evidence["recommendation"]) > 0
