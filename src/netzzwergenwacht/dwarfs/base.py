"""Base classes for Dwarf agents."""

import asyncio
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any


class Severity(Enum):
    """Issue severity levels."""

    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


@dataclass
class Issue:
    """Represents an issue found during analysis."""

    issue_type: str
    severity: Severity
    message: str
    location: str
    evidence: dict[str, Any] = field(default_factory=dict)
    timestamp: datetime = field(default_factory=datetime.now)


@dataclass
class AnalysisResult:
    """Result of a Dwarf analysis."""

    url: str
    dwarf_name: str
    issues: list[Issue]
    metadata: dict[str, Any] = field(default_factory=dict)
    timestamp: datetime = field(default_factory=datetime.now)
    success: bool = True
    error_message: str | None = None


class Dwarf(ABC):
    """Base class for all Dwarf agents."""

    def __init__(self, name: str, description: str = ""):
        self.name = name
        self.description = description

    @abstractmethod
    async def analyze(self, url: str) -> AnalysisResult:
        """Analyze a URL and return findings."""

    def create_issue(
        self,
        issue_type: str,
        severity: Severity,
        message: str,
        location: str,
        evidence: dict[str, Any] | None = None,
    ) -> Issue:
        """Helper method to create an Issue."""
        return Issue(
            issue_type=issue_type,
            severity=severity,
            message=message,
            location=location,
            evidence=evidence or {},
        )


class DwarfOrchestrator:
    """Orchestrates multiple Dwarf agents."""

    def __init__(self):
        self.dwarfs: list[Dwarf] = []

    def add_dwarf(self, dwarf: Dwarf) -> None:
        """Add a Dwarf to the orchestrator."""
        self.dwarfs.append(dwarf)

    async def analyze_url(self, url: str) -> list[AnalysisResult]:
        """Run all registered Dwarfs on a URL."""
        tasks = [dwarf.analyze(url) for dwarf in self.dwarfs]
        results = await asyncio.gather(*tasks, return_exceptions=True)

        processed_results = []
        for i, result in enumerate(results):
            if isinstance(result, Exception):
                # Create error result for failed analysis
                error_result = AnalysisResult(
                    url=url,
                    dwarf_name=self.dwarfs[i].name,
                    issues=[],
                    success=False,
                    error_message=str(result),
                )
                processed_results.append(error_result)
            else:
                processed_results.append(result)

        return processed_results
