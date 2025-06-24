"""Tests for base Dwarf classes."""

from datetime import datetime

import pytest

from netzzwergenwacht.dwarfs.base import (
    AnalysisResult,
    Dwarf,
    DwarfOrchestrator,
    Issue,
    Severity,
)


class MockDwarf(Dwarf):
    """Mock Dwarf for testing."""

    def __init__(self, should_fail: bool = False):
        super().__init__("Mock Dwarf", "A mock dwarf for testing")
        self.should_fail = should_fail

    async def analyze(self, url: str) -> AnalysisResult:
        if self.should_fail:
            raise Exception("Mock failure")

        issue = self.create_issue(
            issue_type="test_issue",
            severity=Severity.LOW,
            message="Test issue",
            location=url,
        )

        return AnalysisResult(url=url, dwarf_name=self.name, issues=[issue])


class TestIssue:
    """Test Issue class."""

    def test_issue_creation(self):
        issue = Issue(
            issue_type="test",
            severity=Severity.HIGH,
            message="Test message",
            location="https://example.com",
        )

        assert issue.issue_type == "test"
        assert issue.severity == Severity.HIGH
        assert issue.message == "Test message"
        assert issue.location == "https://example.com"
        assert isinstance(issue.timestamp, datetime)


class TestAnalysisResult:
    """Test AnalysisResult class."""

    def test_analysis_result_creation(self):
        result = AnalysisResult(
            url="https://example.com", dwarf_name="Test Dwarf", issues=[]
        )

        assert result.url == "https://example.com"
        assert result.dwarf_name == "Test Dwarf"
        assert result.issues == []
        assert result.success
        assert result.error_message is None
        assert isinstance(result.timestamp, datetime)


class TestDwarf:
    """Test base Dwarf class."""

    def test_dwarf_initialization(self):
        dwarf = MockDwarf()
        assert dwarf.name == "Mock Dwarf"
        assert dwarf.description == "A mock dwarf for testing"

    def test_create_issue(self):
        dwarf = MockDwarf()
        issue = dwarf.create_issue(
            issue_type="test",
            severity=Severity.MEDIUM,
            message="Test issue",
            location="https://example.com",
            evidence={"key": "value"},
        )

        assert isinstance(issue, Issue)
        assert issue.issue_type == "test"
        assert issue.severity == Severity.MEDIUM
        assert issue.evidence == {"key": "value"}


class TestDwarfOrchestrator:
    """Test DwarfOrchestrator class."""

    def test_add_dwarf(self):
        orchestrator = DwarfOrchestrator()
        dwarf = MockDwarf()

        orchestrator.add_dwarf(dwarf)
        assert len(orchestrator.dwarfs) == 1
        assert orchestrator.dwarfs[0] == dwarf

    @pytest.mark.asyncio
    async def test_analyze_url_success(self):
        orchestrator = DwarfOrchestrator()
        orchestrator.add_dwarf(MockDwarf())

        results = await orchestrator.analyze_url("https://example.com")

        assert len(results) == 1
        assert results[0].success
        assert len(results[0].issues) == 1

    @pytest.mark.asyncio
    async def test_analyze_url_failure(self):
        orchestrator = DwarfOrchestrator()
        orchestrator.add_dwarf(MockDwarf(should_fail=True))

        results = await orchestrator.analyze_url("https://example.com")

        assert len(results) == 1
        assert not results[0].success
        assert results[0].error_message == "Mock failure"
