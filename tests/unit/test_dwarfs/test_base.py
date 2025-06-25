"""Tests for base Dwarf classes."""

from datetime import datetime

import pytest

from netzzwergenwacht.dwarfs.base import (
    AnalysisResult,
    ComprehensiveAnalysisReport,
    DetailedAnalysisResult,
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
        self.metrics.register_metric("test_metric", lambda _: {"value": 42})

    async def analyze(self, url: str) -> AnalysisResult:
        if self.should_fail:
            raise Exception("Mock failure")

        issue = self.create_issue(
            issue_type="test_issue",
            severity=Severity.LOW,
            message="Test issue",
            location=url,
        )

        return AnalysisResult(
            url=url, dwarf_name=self.name, issues=[issue], metadata={"test": "data"}
        )

    def _get_category(self) -> str:
        return "testing"


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
        assert hasattr(dwarf, "metrics")
        assert hasattr(dwarf, "logger")

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
        assert isinstance(issue.timestamp, datetime)

    @pytest.mark.asyncio
    async def test_analyze_abstract_method(self):
        """Test that analyze() is abstract and must be implemented."""
        with pytest.raises(TypeError):

            class InvalidDwarf(Dwarf):
                pass

            InvalidDwarf("Invalid")

    @pytest.mark.asyncio
    async def test_default_analyze_detailed_implementation(self):
        """Test the default analyze_detailed implementation."""
        dwarf = MockDwarf()
        result = await dwarf.analyze_detailed("https://example.com")

        assert isinstance(result, DetailedAnalysisResult)
        assert result.url == "https://example.com"
        assert result.dwarf_name == dwarf.name
        assert result.success

    def test_metrics_collection(self):
        """Test metrics collector registration and collection."""
        dwarf = MockDwarf()

        # Register a test metric
        def test_metric(d):
            return {"test": 42}

        dwarf.metrics.register_metric("test_metric", test_metric)

        # Collect metrics
        metrics = dwarf.metrics.collect_all(dwarf)

        assert "test_metric" in metrics
        assert metrics["test_metric"] == {"test": 42}


class TestDwarfOrchestrator:
    """Test DwarfOrchestrator class."""

    def test_add_dwarf(self):
        orchestrator = DwarfOrchestrator()
        dwarf = MockDwarf()

        orchestrator.add_dwarf(dwarf)
        assert len(orchestrator.dwarfs) == 1
        assert orchestrator.dwarfs[0] == dwarf

    def test_add_multiple_dwarfs(self):
        orchestrator = DwarfOrchestrator()
        dwarfs = [MockDwarf() for _ in range(3)]

        for dwarf in dwarfs:
            orchestrator.add_dwarf(dwarf)

        assert len(orchestrator.dwarfs) == 3
        assert all(d in orchestrator.dwarfs for d in dwarfs)

    @pytest.mark.asyncio
    async def test_analyze_url_success(self):
        orchestrator = DwarfOrchestrator()
        orchestrator.add_dwarf(MockDwarf())

        results = await orchestrator.analyze_url("https://example.com")

        assert len(results) == 1
        assert results[0].success
        assert len(results[0].issues) == 1
        assert isinstance(results[0].timestamp, datetime)

    @pytest.mark.asyncio
    async def test_analyze_url_failure(self):
        orchestrator = DwarfOrchestrator()
        orchestrator.add_dwarf(MockDwarf(should_fail=True))

        results = await orchestrator.analyze_url("https://example.com")

        assert len(results) == 1
        assert not results[0].success
        assert results[0].error_message == "Mock failure"
        assert isinstance(results[0].timestamp, datetime)

    @pytest.mark.asyncio
    async def test_analyze_url_multiple_dwarfs(self):
        orchestrator = DwarfOrchestrator()
        orchestrator.add_dwarf(MockDwarf())
        orchestrator.add_dwarf(MockDwarf(should_fail=True))
        orchestrator.add_dwarf(MockDwarf())

        results = await orchestrator.analyze_url("https://example.com")

        assert len(results) == 3
        assert sum(1 for r in results if r.success) == 2
        assert sum(1 for r in results if not r.success) == 1

    @pytest.mark.asyncio
    async def test_analyze_url_detailed(self):
        orchestrator = DwarfOrchestrator()
        orchestrator.add_dwarf(MockDwarf())

        report = await orchestrator.analyze_url_detailed("https://example.com")

        assert isinstance(report, ComprehensiveAnalysisReport)
        assert report.url == "https://example.com"
        assert len(report.dwarf_results) == 1
        assert report.dwarf_results[0].success
