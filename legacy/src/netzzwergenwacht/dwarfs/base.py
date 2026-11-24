"""Base classes and mixins for Dwarf agents."""

import asyncio
import logging
from abc import ABC, abstractmethod
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any, TypeVar

T = TypeVar("T", bound="Dwarf")


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


# New detailed structures for LLM integration
@dataclass
class CodeLocation:
    """Detailed location information for code issues."""

    file_path: str | None = None  # e.g., "index.html", "main.css", "app.js"
    line_number: int | None = None  # Line number in the file
    column_number: int | None = None  # Column number
    element_selector: str | None = (
        None  # CSS selector, e.g., "meta[name='description']"
    )
    element_tag: str | None = None  # HTML tag name, e.g., "meta", "img", "a"
    element_id: str | None = None  # Element ID
    element_class: str | None = None  # Element class
    attribute_name: str | None = None  # Attribute name, e.g., "alt", "lang", "src"
    attribute_value: str | None = None  # Current attribute value
    context_before: str | None = None  # Code context before the issue
    context_after: str | None = None  # Code context after the issue
    full_element: str | None = None  # Complete HTML element
    url_path: str | None = None  # URL path where issue was found
    resource_type: str | None = None  # "html", "css", "js", "image", "api"


@dataclass
class DetailedIssue:
    """Enhanced issue with detailed information for LLM analysis."""

    issue_type: str
    severity: Severity
    message: str
    location: str
    category: str  # e.g., "performance", "security", "accessibility"
    subcategory: str  # e.g., "core_web_vitals", "ssl", "wcag"
    description: str
    impact: str  # User-facing impact description
    technical_details: dict[str, Any] = field(default_factory=dict)
    recommendations: list[str] = field(default_factory=list)
    related_issues: list[str] = field(default_factory=list)  # IDs of related issues
    evidence: dict[str, Any] = field(default_factory=dict)
    timestamp: datetime = field(default_factory=datetime.now)
    priority_score: float = 0.0  # 0.0-1.0 priority for LLM

    # New detailed location information
    code_location: CodeLocation | None = None
    fix_suggestions: list[str] = field(default_factory=list)  # Specific code fixes
    affected_elements: list[str] = field(
        default_factory=list
    )  # List of affected elements
    browser_console_errors: list[str] = field(default_factory=list)  # JS console errors
    network_errors: list[str] = field(default_factory=list)  # Network request errors


@dataclass
class PerformanceMetrics:
    """Detailed performance metrics."""

    # Core Web Vitals
    lcp: float | None = None  # Largest Contentful Paint
    fcp: float | None = None  # First Contentful Paint
    cls: float | None = None  # Cumulative Layout Shift
    fid: float | None = None  # First Input Delay
    ttfb: float | None = None  # Time to First Byte

    # Traditional metrics
    response_time_ms: float | None = None
    page_load_time_ms: float | None = None
    dom_content_loaded_ms: float | None = None

    # Resource metrics
    total_resources: int = 0
    total_size_bytes: int = 0
    compressed_size_bytes: int | None = None
    image_count: int = 0
    css_count: int = 0
    js_count: int = 0

    # Performance scores
    performance_score: float | None = None  # 0-100
    accessibility_score: float | None = None  # 0-100
    best_practices_score: float | None = None  # 0-100
    seo_score: float | None = None  # 0-100


@dataclass
class SecurityMetrics:
    """Detailed security metrics."""

    # SSL/TLS
    ssl_enabled: bool = False
    ssl_version: str | None = None
    certificate_valid: bool = False
    certificate_expiry_days: int | None = None
    certificate_issuer: str | None = None

    # Security headers
    hsts_enabled: bool = False
    hsts_max_age: int | None = None
    csp_enabled: bool = False
    x_frame_options: str | None = None
    x_content_type_options: str | None = None
    referrer_policy: str | None = None

    # Vulnerability scan results
    open_ports: list[int] = field(default_factory=list)
    dangerous_services: list[str] = field(default_factory=list)
    information_disclosure: list[str] = field(default_factory=list)

    # Security scores
    security_score: float | None = None  # 0-100
    ssl_score: float | None = None  # 0-100
    headers_score: float | None = None  # 0-100


@dataclass
class AccessibilityMetrics:
    """Detailed accessibility metrics."""

    # WCAG compliance
    wcag_2_1_aa_compliance: float = 0.0  # 0.0-1.0
    wcag_2_1_aaa_compliance: float = 0.0  # 0.0-1.0

    # Specific checks
    alt_text_missing: int = 0
    contrast_issues: int = 0
    keyboard_navigation_issues: int = 0
    focus_management_issues: int = 0
    aria_issues: int = 0
    semantic_structure_issues: int = 0

    # Mobile accessibility
    touch_target_issues: int = 0
    viewport_issues: int = 0
    font_size_issues: int = 0

    # Detailed breakdown
    wcag_violations: dict[str, list[str]] = field(default_factory=dict)
    eaa_violations: dict[str, list[str]] = field(default_factory=dict)

    # Accessibility scores
    accessibility_score: float | None = None  # 0-100
    mobile_accessibility_score: float | None = None  # 0-100


@dataclass
class SEOMetrics:
    """Detailed SEO metrics."""

    # Meta tags
    title_length: int | None = None
    description_length: int | None = None
    keywords_present: bool = False

    # Content structure
    h1_count: int = 0
    h2_count: int = 0
    h3_count: int = 0
    heading_structure_valid: bool = True

    # Social media
    og_tags_present: bool = False
    twitter_cards_present: bool = False

    # Technical SEO
    canonical_url: str | None = None
    robots_txt_present: bool = False
    sitemap_present: bool = False
    structured_data_present: bool = False

    # Content quality
    content_length: int = 0
    readability_score: float | None = None
    duplicate_content_detected: bool = False

    # SEO scores
    seo_score: float | None = None  # 0-100
    content_score: float | None = None  # 0-100
    technical_seo_score: float | None = None  # 0-100


@dataclass
class VisualMetrics:
    """Detailed visual analysis metrics."""

    # Layout analysis
    layout_issues: int = 0
    overlapping_elements: int = 0
    overflow_issues: int = 0

    # Color analysis
    color_contrast_issues: int = 0
    color_scheme_consistent: bool = True
    brand_colors_detected: list[str] = field(default_factory=list)

    # UI elements
    button_count: int = 0
    form_count: int = 0
    navigation_elements: int = 0

    # Responsive design
    responsive_breakpoints: list[str] = field(default_factory=list)
    mobile_friendly: bool = True
    tablet_friendly: bool = True

    # Screenshots
    screenshots: dict[str, str] = field(default_factory=dict)  # viewport -> path

    # Visual scores
    visual_consistency_score: float | None = None  # 0-100
    ui_quality_score: float | None = None  # 0-100

    # Additional visual metrics
    screenshot_path: str | None = None
    dominant_colors: list[str] = field(default_factory=list)
    navigation_issues: int = 0
    color_palette_size: int = 0


@dataclass
class ContentMetrics:
    """Detailed content analysis metrics."""

    # Content statistics
    word_count: int = 0
    character_count: int = 0
    sentence_count: int = 0
    paragraph_count: int = 0

    # Readability
    readability_score: float | None = None  # Flesch Reading Ease
    complex_sentences: int = 0
    average_sentence_length: float | None = None

    # Content quality
    spelling_errors: int = 0
    grammar_issues: int = 0
    duplicate_content_ratio: float = 0.0

    # Structure
    heading_structure_issues: int = 0
    paragraph_length_issues: int = 0

    # Content freshness
    content_age_days: int = 0
    last_modified: str | None = None
    publication_date: str | None = None

    # Content scores
    content_quality_score: float | None = None  # 0-100
    structure_score: float | None = None  # 0-100


@dataclass
class DetailedAnalysisResult:
    """Comprehensive analysis result with detailed metrics for LLM."""

    url: str
    dwarf_name: str
    timestamp: datetime = field(default_factory=datetime.now)
    success: bool = True
    error_message: str | None = None

    # Detailed issues
    detailed_issues: list[DetailedIssue] = field(default_factory=list)

    # Specific metrics based on dwarf type
    performance_metrics: PerformanceMetrics | None = None
    security_metrics: SecurityMetrics | None = None
    accessibility_metrics: AccessibilityMetrics | None = None
    seo_metrics: SEOMetrics | None = None
    visual_metrics: VisualMetrics | None = None
    content_metrics: ContentMetrics | None = None

    # Raw data for LLM analysis
    raw_data: dict[str, Any] = field(default_factory=dict)

    # Correlation data
    related_urls: list[str] = field(default_factory=list)
    dependencies: list[str] = field(default_factory=list)


@dataclass
class ComprehensiveAnalysisReport:
    """Complete analysis report combining all dwarf results for LLM."""

    url: str
    timestamp: datetime = field(default_factory=datetime.now)
    analysis_duration_seconds: float = 0.0

    # All dwarf results
    dwarf_results: list[DetailedAnalysisResult] = field(default_factory=list)

    # Aggregated metrics
    overall_score: float | None = None  # 0-100
    performance_score: float | None = None
    security_score: float | None = None
    accessibility_score: float | None = None
    seo_score: float | None = None
    visual_score: float | None = None

    # Issue summary
    total_issues: int = 0
    critical_issues: int = 0
    high_issues: int = 0
    medium_issues: int = 0
    low_issues: int = 0

    # Issue categories
    issues_by_category: dict[str, int] = field(default_factory=dict)
    issues_by_dwarf: dict[str, int] = field(default_factory=dict)

    # Recommendations
    top_recommendations: list[str] = field(default_factory=list)
    priority_actions: list[str] = field(default_factory=list)

    # Technical details
    technical_summary: dict[str, Any] = field(default_factory=dict)
    screenshots: dict[str, str] = field(default_factory=dict)


class AnalysisMixin:
    """Mixin for core analysis capabilities."""

    @abstractmethod
    async def analyze(self, url: str) -> AnalysisResult:
        """Analyze a URL and return findings."""


class DetailedAnalysisMixin:
    """Mixin for detailed analysis capabilities."""

    @abstractmethod
    async def analyze_detailed(self, url: str) -> DetailedAnalysisResult:
        """Analyze a URL with detailed metrics for LLM integration."""


class IssueCreationMixin:
    """Mixin for standardized issue creation."""

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

    def create_detailed_issue(
        self,
        issue_type: str,
        severity: Severity,
        message: str,
        location: str,
        category: str,
        subcategory: str,
        description: str,
        impact: str,
        technical_details: dict[str, Any] | None = None,
        recommendations: list[str] | None = None,
        evidence: dict[str, Any] | None = None,
        priority_score: float = 0.0,
        code_location: CodeLocation | None = None,
        fix_suggestions: list[str] | None = None,
        affected_elements: list[str] | None = None,
        browser_console_errors: list[str] | None = None,
        network_errors: list[str] | None = None,
    ) -> DetailedIssue:
        """Helper method to create a DetailedIssue."""
        return DetailedIssue(
            issue_type=issue_type,
            severity=severity,
            message=message,
            location=location,
            category=category,
            subcategory=subcategory,
            description=description,
            impact=impact,
            technical_details=technical_details or {},
            recommendations=recommendations or [],
            evidence=evidence or {},
            priority_score=priority_score,
            code_location=code_location,
            fix_suggestions=fix_suggestions or [],
            affected_elements=affected_elements or [],
            browser_console_errors=browser_console_errors or [],
            network_errors=network_errors or [],
        )


class MetricsCollector:
    """Standardized metrics collection registry."""

    def __init__(self) -> None:
        self._metrics_registry: dict[str, Callable[[Any], Any]] = {}

    def register_metric(self, name: str, collector: Callable[[Any], Any]) -> None:
        """Register a metric collection function."""
        self._metrics_registry[name] = collector

    def collect_all(self, dwarf: Any) -> dict[str, Any]:
        """Collect all registered metrics."""
        return {
            name: collector(dwarf) for name, collector in self._metrics_registry.items()
        }


class Dwarf(AnalysisMixin, DetailedAnalysisMixin, IssueCreationMixin, ABC):
    """Base class for all Dwarf agents."""

    def __init__(self, name: str, description: str = ""):
        self.name = name
        self.description = description
        self.logger = logging.getLogger(f"dwarf.{name}")
        self.metrics = MetricsCollector()

    @abstractmethod
    async def analyze(self, url: str) -> AnalysisResult:
        """Analyze a URL and return findings."""

    async def analyze_detailed(self, url: str) -> DetailedAnalysisResult:
        """Analyze a URL and return detailed findings for LLM."""
        # Default implementation - override in subclasses
        basic_result = await self.analyze(url)

        return DetailedAnalysisResult(
            url=basic_result.url,
            dwarf_name=basic_result.dwarf_name,
            timestamp=basic_result.timestamp,
            success=basic_result.success,
            error_message=basic_result.error_message,
            detailed_issues=[
                DetailedIssue(
                    issue_type=issue.issue_type,
                    severity=issue.severity,
                    message=issue.message,
                    location=issue.location,
                    category=self._get_category(),
                    subcategory=issue.issue_type,
                    description=issue.message,
                    impact=self._get_impact_description(issue),
                    technical_details=issue.evidence,
                    recommendations=self._get_recommendations(issue),
                    evidence=issue.evidence,
                    timestamp=issue.timestamp,
                )
                for issue in basic_result.issues
            ],
            raw_data=basic_result.metadata,
        )

    def _get_category(self) -> str:
        """Get the category for this dwarf's issues."""
        return "general"

    def _get_impact_description(self, issue: Issue) -> str:
        """Get user-facing impact description for an issue."""
        return f"This issue may affect {self._get_category()} of the website."

    def _get_recommendations(self, issue: Issue) -> list[str]:
        """Get recommendations for fixing an issue."""
        return [f"Review and fix the {issue.issue_type} issue"]

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

    def create_detailed_issue(
        self,
        issue_type: str,
        severity: Severity,
        message: str,
        location: str,
        category: str,
        subcategory: str,
        description: str,
        impact: str,
        technical_details: dict[str, Any] | None = None,
        recommendations: list[str] | None = None,
        evidence: dict[str, Any] | None = None,
        priority_score: float = 0.0,
        code_location: CodeLocation | None = None,
        fix_suggestions: list[str] | None = None,
        affected_elements: list[str] | None = None,
        browser_console_errors: list[str] | None = None,
        network_errors: list[str] | None = None,
    ) -> DetailedIssue:
        """Helper method to create a DetailedIssue."""
        return DetailedIssue(
            issue_type=issue_type,
            severity=severity,
            message=message,
            location=location,
            category=category,
            subcategory=subcategory,
            description=description,
            impact=impact,
            technical_details=technical_details or {},
            recommendations=recommendations or [],
            evidence=evidence or {},
            priority_score=priority_score,
            code_location=code_location,
            fix_suggestions=fix_suggestions or [],
            affected_elements=affected_elements or [],
            browser_console_errors=browser_console_errors or [],
            network_errors=network_errors or [],
        )


class DwarfOrchestrator:
    """Orchestrates multiple Dwarf agents."""

    def __init__(self) -> None:
        self.dwarfs: list[Dwarf] = []

    def add_dwarf(self, dwarf: Dwarf) -> None:
        """Add a Dwarf to the orchestrator."""
        self.dwarfs.append(dwarf)

    async def analyze_url(self, url: str) -> list[AnalysisResult]:
        """Run all registered Dwarfs on a URL."""
        tasks = [dwarf.analyze(url) for dwarf in self.dwarfs]
        results = await asyncio.gather(*tasks, return_exceptions=True)

        processed_results: list[AnalysisResult] = []
        for i, result in enumerate(results):
            if isinstance(result, BaseException):
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

    async def analyze_url_detailed(self, url: str) -> ComprehensiveAnalysisReport:
        """Run all registered Dwarfs on a URL and return detailed results for LLM."""
        import time

        start_time = time.time()

        tasks = [dwarf.analyze_detailed(url) for dwarf in self.dwarfs]
        results = await asyncio.gather(*tasks, return_exceptions=True)

        analysis_duration = time.time() - start_time

        processed_results: list[DetailedAnalysisResult] = []
        for i, result in enumerate(results):
            if isinstance(result, BaseException):
                # Create error result for failed analysis
                error_result = DetailedAnalysisResult(
                    url=url,
                    dwarf_name=self.dwarfs[i].name,
                    success=False,
                    error_message=str(result),
                )
                processed_results.append(error_result)
            else:
                processed_results.append(result)

        # Create comprehensive report
        return self._create_comprehensive_report(
            url, processed_results, analysis_duration
        )

    def _create_comprehensive_report(
        self, url: str, results: list[DetailedAnalysisResult], duration: float
    ) -> ComprehensiveAnalysisReport:
        """Create a comprehensive analysis report from all dwarf results."""

        # Aggregate issues
        all_issues = []
        for result in results:
            all_issues.extend(result.detailed_issues)

        # Count issues by severity
        severity_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}
        for issue in all_issues:
            severity_counts[issue.severity.value] += 1

        # Count issues by category
        issues_by_category: dict[str, int] = {}
        issues_by_dwarf = {}
        for result in results:
            dwarf_issues = len(result.detailed_issues)
            issues_by_dwarf[result.dwarf_name] = dwarf_issues

            for issue in result.detailed_issues:
                category = issue.category
                issues_by_category[category] = issues_by_category.get(category, 0) + 1

        # Calculate overall scores (simple average for now)
        scores = []
        for result in results:
            if hasattr(result, "performance_metrics") and result.performance_metrics:
                if result.performance_metrics.performance_score:
                    scores.append(result.performance_metrics.performance_score)

        overall_score = sum(scores) / len(scores) if scores else None

        return ComprehensiveAnalysisReport(
            url=url,
            timestamp=datetime.now(),
            analysis_duration_seconds=duration,
            dwarf_results=results,
            overall_score=overall_score,
            total_issues=len(all_issues),
            critical_issues=severity_counts["critical"],
            high_issues=severity_counts["high"],
            medium_issues=severity_counts["medium"],
            low_issues=severity_counts["low"],
            issues_by_category=issues_by_category,
            issues_by_dwarf=issues_by_dwarf,
            top_recommendations=self._extract_top_recommendations(all_issues),
            priority_actions=self._extract_priority_actions(all_issues),
        )

    def _extract_top_recommendations(self, issues: list[DetailedIssue]) -> list[str]:
        """Extract top recommendations from issues."""
        recommendations = []
        for issue in issues:
            if issue.severity in [Severity.CRITICAL, Severity.HIGH]:
                recommendations.extend(issue.recommendations)
        return list(set(recommendations))[:5]  # Top 5 unique recommendations

    def _extract_priority_actions(self, issues: list[DetailedIssue]) -> list[str]:
        """Extract priority actions from critical and high severity issues."""
        actions = []
        for issue in issues:
            if issue.severity in [Severity.CRITICAL, Severity.HIGH]:
                actions.append(f"Fix {issue.issue_type}: {issue.message}")
        return actions[:10]  # Top 10 priority actions
