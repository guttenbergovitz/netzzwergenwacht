"""PDF Report Generator for NetzZwergenWacht analysis results."""

from pathlib import Path
from typing import Any

from reportlab.lib import colors
from reportlab.lib.pagesizes import letter
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import inch
from reportlab.platypus import (
    PageBreak,
    Paragraph,
    SimpleDocTemplate,
    Spacer,
    Table,
    TableStyle,
)

from ..dwarfs.base import ComprehensiveAnalysisReport, DetailedIssue


class PDFReportGenerator:
    """Generates professional PDF reports from NetzZwergenWacht analysis results."""

    def __init__(
        self, report_type: str = "comprehensive", llm_results: dict | None = None
    ):
        """Initialize PDF generator.

        Args:
            report_type: Type of report ("executive", "technical", "comprehensive")
            llm_results: Optional LLM analysis results to integrate into the report
        """
        self.report_type = report_type
        self.llm_results = llm_results or {}
        self.styles = getSampleStyleSheet()
        self._setup_custom_styles()

    def _setup_custom_styles(self) -> None:
        """Setup custom paragraph styles for the report."""
        # Executive style for headers
        self.styles.add(
            ParagraphStyle(
                name="ExecutiveHeader",
                parent=self.styles["Heading1"],
                fontSize=18,
                spaceAfter=20,
                textColor=colors.HexColor("#2E4057"),
                fontName="Helvetica-Bold",
            )
        )

        # Issue severity styles
        self.styles.add(
            ParagraphStyle(
                name="CriticalIssue",
                parent=self.styles["Normal"],
                fontSize=12,
                textColor=colors.red,
                fontName="Helvetica-Bold",
            )
        )

        self.styles.add(
            ParagraphStyle(
                name="HighIssue",
                parent=self.styles["Normal"],
                fontSize=11,
                textColor=colors.orange,
                fontName="Helvetica-Bold",
            )
        )

        # Code style for fix suggestions
        self.styles.add(
            ParagraphStyle(
                name="CodeStyle",
                parent=self.styles["Code"],
                fontSize=10,
                backColor=colors.HexColor("#f8f9fa"),
                borderColor=colors.HexColor("#dee2e6"),
                borderWidth=1,
                borderPadding=8,
                fontName="Courier",
            )
        )

    def generate_report(
        self, report: ComprehensiveAnalysisReport, output_path: Path
    ) -> None:
        """Generate PDF report from analysis results.

        Args:
            report: Comprehensive analysis report data
            output_path: Path where PDF should be saved
        """
        # Ensure output directory exists
        output_path.parent.mkdir(parents=True, exist_ok=True)

        # Create PDF document
        doc = SimpleDocTemplate(
            str(output_path),
            pagesize=letter,
            rightMargin=72,
            leftMargin=72,
            topMargin=72,
            bottomMargin=72,
        )

        # Build report content
        story = []

        # Title page
        story.extend(self._build_title_page(report))
        story.append(PageBreak())

        # Executive summary
        story.extend(self._build_executive_summary(report))
        story.append(PageBreak())

        # Detailed analysis by dwarf
        story.extend(self._build_detailed_analysis(report))
        story.append(PageBreak())

        # Recommendations and action items
        story.extend(self._build_recommendations(report))

        # Build PDF
        doc.build(story)

    def _build_title_page(self, report: ComprehensiveAnalysisReport) -> list[Any]:
        """Build the title page of the report."""
        story = []

        # Main title
        title = Paragraph(
            "NetzZwergenWacht<br/>Website Quality Analysis Report",
            self.styles["ExecutiveHeader"],
        )
        story.append(title)
        story.append(Spacer(1, 0.5 * inch))

        # URL and timestamp
        info_data = [
            ["Website URL:", report.url],
            [
                "Analysis Date:",
                report.timestamp.strftime("%Y-%m-%d %H:%M:%S")
                if report.timestamp
                else "N/A",
            ],
            ["Analysis Duration:", f"{report.analysis_duration_seconds:.2f} seconds"],
            ["Report Type:", self.report_type.title()],
            ["Total Issues Found:", str(report.total_issues)],
        ]

        if report.overall_score:
            info_data.append([
                "Overall Quality Score:",
                f"{report.overall_score:.1f}/100",
            ])

        info_table = Table(info_data, colWidths=[2.5 * inch, 3 * inch])
        info_table.setStyle(
            TableStyle([
                ("ALIGN", (0, 0), (-1, -1), "LEFT"),
                ("FONTNAME", (0, 0), (0, -1), "Helvetica-Bold"),
                ("FONTNAME", (1, 0), (1, -1), "Helvetica"),
                ("FONTSIZE", (0, 0), (-1, -1), 12),
                ("GRID", (0, 0), (-1, -1), 1, colors.grey),
                ("VALIGN", (0, 0), (-1, -1), "TOP"),
            ])
        )

        story.append(info_table)
        story.append(Spacer(1, 0.5 * inch))

        # Issues breakdown
        if report.total_issues > 0:
            story.append(
                Paragraph("Issues Breakdown by Severity", self.styles["Heading2"])
            )

            severity_data = [
                ["Severity Level", "Count", "Percentage"],
                [
                    "Critical",
                    str(report.critical_issues),
                    f"{(report.critical_issues / report.total_issues) * 100:.1f}%",
                ],
                [
                    "High",
                    str(report.high_issues),
                    f"{(report.high_issues / report.total_issues) * 100:.1f}%",
                ],
                [
                    "Medium",
                    str(report.medium_issues),
                    f"{(report.medium_issues / report.total_issues) * 100:.1f}%",
                ],
                [
                    "Low",
                    str(report.low_issues),
                    f"{(report.low_issues / report.total_issues) * 100:.1f}%",
                ],
            ]

            severity_table = Table(
                severity_data, colWidths=[2 * inch, 1 * inch, 1.5 * inch]
            )
            severity_table.setStyle(
                TableStyle([
                    ("BACKGROUND", (0, 0), (-1, 0), colors.grey),
                    ("TEXTCOLOR", (0, 0), (-1, 0), colors.whitesmoke),
                    ("ALIGN", (0, 0), (-1, -1), "CENTER"),
                    ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
                    ("FONTSIZE", (0, 0), (-1, 0), 12),
                    ("FONTSIZE", (0, 1), (-1, -1), 10),
                    ("GRID", (0, 0), (-1, -1), 1, colors.black),
                    (
                        "ROWBACKGROUNDS",
                        (0, 1),
                        (-1, -1),
                        [colors.white, colors.lightgrey],
                    ),
                ])
            )

            story.append(severity_table)

        return story

    def _build_executive_summary(
        self, report: ComprehensiveAnalysisReport
    ) -> list[Any]:
        """Build executive summary section."""
        story = []

        story.append(Paragraph("Executive Summary", self.styles["ExecutiveHeader"]))

        # Use LLM-generated summary if available
        if self.llm_results.get("success") and self.llm_results.get("analysis"):
            story.append(Paragraph("🤖 AI-Generated Analysis", self.styles["Heading3"]))

            # Extract executive summary from LLM analysis
            llm_analysis = self.llm_results["analysis"]
            executive_section = self._extract_section_from_llm(
                llm_analysis, "Executive Summary"
            )

            if executive_section:
                # Clean and format the LLM summary
                cleaned_summary = self._clean_llm_text_for_pdf(executive_section)
                story.append(Paragraph(cleaned_summary, self.styles["Normal"]))
            else:
                # Fallback to using first paragraph of LLM analysis
                first_paragraph = llm_analysis.split("\n\n")[0] if llm_analysis else ""
                if first_paragraph:
                    cleaned_summary = self._clean_llm_text_for_pdf(first_paragraph)
                    story.append(Paragraph(cleaned_summary, self.styles["Normal"]))

            story.append(Spacer(1, 0.2 * inch))

            # Add usage info if available
            if self.llm_results.get("usage"):
                usage = self.llm_results["usage"]
                usage_text = f"<i>Analysis powered by {self.llm_results.get('model', 'AI')} • Cost: ${usage['cost']:.4f} • Tokens: {usage['total_tokens']}</i>"
                story.append(Paragraph(usage_text, self.styles["Normal"]))
                story.append(Spacer(1, 0.3 * inch))

        # Overall assessment with scores
        if report.overall_score:
            if report.overall_score >= 80:
                assessment = "The website demonstrates excellent quality standards with minimal issues."
                score_color = "green"
            elif report.overall_score >= 60:
                assessment = "The website shows good quality but has several areas for improvement."
                score_color = "orange"
            else:
                assessment = "The website requires significant improvements to meet quality standards."
                score_color = "red"

            summary_text = f"""
            <b>Overall Quality Score: <font color="{score_color}">{report.overall_score:.1f}/100</font></b><br/><br/>
            {assessment}<br/><br/>
            This analysis identified <b>{report.total_issues} total issues</b> across {len(report.dwarf_results)} analysis categories,
            with <b>{report.critical_issues} critical</b> and <b>{report.high_issues} high-priority</b> issues requiring immediate attention.
            """
        else:
            summary_text = f"""
            This comprehensive analysis identified <b>{report.total_issues} issues</b> across {len(report.dwarf_results)}
            analysis categories. <b>{report.critical_issues + report.high_issues} high-priority issues</b> require immediate attention.
            """

        story.append(Paragraph(summary_text, self.styles["Normal"]))
        story.append(Spacer(1, 0.3 * inch))

        # Issues by category
        if report.issues_by_category:
            story.append(Paragraph("Issues by Category", self.styles["Heading2"]))

            category_data = [["Category", "Issues Found", "Priority Level"]]
            for category, count in sorted(report.issues_by_category.items()):
                priority = self._categorize_priority(category, count)
                category_data.append([category.title(), str(count), priority])

            category_table = Table(
                category_data, colWidths=[2 * inch, 1.5 * inch, 1.5 * inch]
            )
            category_table.setStyle(
                TableStyle([
                    ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#2E4057")),
                    ("TEXTCOLOR", (0, 0), (-1, 0), colors.whitesmoke),
                    ("ALIGN", (0, 0), (-1, -1), "LEFT"),
                    ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
                    ("FONTSIZE", (0, 0), (-1, 0), 12),
                    ("FONTSIZE", (0, 1), (-1, -1), 10),
                    ("GRID", (0, 0), (-1, -1), 1, colors.black),
                    (
                        "ROWBACKGROUNDS",
                        (0, 1),
                        (-1, -1),
                        [colors.white, colors.lightgrey],
                    ),
                ])
            )

            story.append(category_table)

        return story

    def _build_detailed_analysis(
        self, report: ComprehensiveAnalysisReport
    ) -> list[Any]:
        """Build detailed analysis section with findings from each Dwarf."""
        story = []

        # Adjust section based on report type
        if self.report_type == "executive":
            story.append(
                Paragraph("Key Findings Summary", self.styles["ExecutiveHeader"])
            )
            return self._build_executive_findings(report)
        else:
            story.append(
                Paragraph("Detailed Analysis Results", self.styles["ExecutiveHeader"])
            )

        for result in report.dwarf_results:
            if not result.success:
                continue

            story.append(
                Paragraph(f"{result.dwarf_name} Analysis", self.styles["Heading2"])
            )

            if not result.detailed_issues:
                story.append(
                    Paragraph(
                        "✓ No issues found in this category.", self.styles["Normal"]
                    )
                )
                story.append(Spacer(1, 0.2 * inch))
                continue

            # Group issues by severity
            critical_issues = [
                i for i in result.detailed_issues if i.severity.value == "critical"
            ]
            high_issues = [
                i for i in result.detailed_issues if i.severity.value == "high"
            ]
            medium_issues = [
                i for i in result.detailed_issues if i.severity.value == "medium"
            ]
            low_issues = [
                i for i in result.detailed_issues if i.severity.value == "low"
            ]

            # Display critical and high issues with details
            for issues, title, _style in [
                (critical_issues, "Critical Issues", "CriticalIssue"),
                (high_issues, "High Priority Issues", "HighIssue"),
            ]:
                if issues:
                    story.append(Paragraph(title, self.styles["Heading3"]))
                    for issue in issues:
                        story.extend(self._format_detailed_issue(issue))
                    story.append(Spacer(1, 0.2 * inch))

            # Summary table for medium and low issues
            if medium_issues or low_issues:
                story.append(
                    Paragraph("Additional Issues Summary", self.styles["Heading3"])
                )

                issue_data = [["Issue", "Severity", "Description"]]

                for issue in medium_issues + low_issues:
                    issue_data.append([
                        issue.issue_type.replace("_", " ").title(),
                        issue.severity.value.title(),
                        issue.message[:100] + "..."
                        if len(issue.message) > 100
                        else issue.message,
                    ])

                issue_table = Table(
                    issue_data, colWidths=[2 * inch, 1 * inch, 3 * inch]
                )
                issue_table.setStyle(
                    TableStyle([
                        ("BACKGROUND", (0, 0), (-1, 0), colors.grey),
                        ("TEXTCOLOR", (0, 0), (-1, 0), colors.whitesmoke),
                        ("ALIGN", (0, 0), (-1, -1), "LEFT"),
                        ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
                        ("FONTSIZE", (0, 0), (-1, 0), 10),
                        ("FONTSIZE", (0, 1), (-1, -1), 9),
                        ("GRID", (0, 0), (-1, -1), 1, colors.black),
                        ("VALIGN", (0, 0), (-1, -1), "TOP"),
                    ])
                )

                story.append(issue_table)

            story.append(Spacer(1, 0.3 * inch))

        return story

    def _build_executive_findings(
        self, report: ComprehensiveAnalysisReport
    ) -> list[Any]:
        """Build executive-level findings summary."""
        story = []

        # Collect all critical and high issues
        critical_issues = []
        high_issues = []

        for result in report.dwarf_results:
            if result.success:
                for issue in result.detailed_issues:
                    if issue.severity.value == "critical":
                        critical_issues.append((result.dwarf_name, issue))
                    elif issue.severity.value == "high":
                        high_issues.append((result.dwarf_name, issue))

        # Critical issues section
        if critical_issues:
            story.append(
                Paragraph(
                    "Critical Issues Requiring Immediate Action",
                    self.styles["Heading2"],
                )
            )
            for dwarf_name, issue in critical_issues:
                story.append(
                    Paragraph(
                        f"<b>{issue.issue_type.replace('_', ' ').title()}</b> ({dwarf_name})",
                        self.styles["CriticalIssue"],
                    )
                )
                story.append(
                    Paragraph(f"Impact: {issue.impact}", self.styles["Normal"])
                )
                if issue.fix_suggestions:
                    story.append(
                        Paragraph(
                            f"Quick Fix: {issue.fix_suggestions[0]}",
                            self.styles["Normal"],
                        )
                    )
                story.append(Spacer(1, 0.1 * inch))

        # High priority issues section
        if high_issues:
            story.append(Paragraph("High Priority Issues", self.styles["Heading2"]))
            for dwarf_name, issue in high_issues[
                :5
            ]:  # Limit to top 5 for executive view
                story.append(
                    Paragraph(
                        f"• {issue.issue_type.replace('_', ' ').title()} ({dwarf_name})",
                        self.styles["HighIssue"],
                    )
                )
                story.append(Paragraph(f"  {issue.impact}", self.styles["Normal"]))
            story.append(Spacer(1, 0.2 * inch))

        # Categories overview
        story.append(Paragraph("Analysis Categories Overview", self.styles["Heading2"]))
        for result in report.dwarf_results:
            if result.success and result.detailed_issues:
                issue_count = len(result.detailed_issues)
                category_summary = (
                    f"<b>{result.dwarf_name}:</b> {issue_count} issues found"
                )

                # Add severity breakdown
                severities: dict[str, int] = {}
                for issue in result.detailed_issues:
                    sev = issue.severity.value
                    severities[sev] = severities.get(sev, 0) + 1

                if severities:
                    breakdown = ", ".join([
                        f"{sev}: {count}" for sev, count in severities.items()
                    ])
                    category_summary += f" ({breakdown})"

                story.append(Paragraph(category_summary, self.styles["Normal"]))

        return story

    def _format_detailed_issue(self, issue: DetailedIssue) -> list[Any]:
        """Format a detailed issue for PDF display."""
        story = []

        # Issue title and severity
        title_text = f"<b>{issue.issue_type.replace('_', ' ').title()}</b> ({issue.severity.value.upper()})"
        story.append(Paragraph(title_text, self.styles["Normal"]))

        # Description and impact
        desc_text = (
            f"<b>Problem:</b> {issue.description}<br/><b>Impact:</b> {issue.impact}"
        )
        story.append(Paragraph(desc_text, self.styles["Normal"]))

        # Location if available
        if issue.code_location and issue.code_location.element_selector:
            location_text = f"<b>Location:</b> {issue.code_location.element_selector}"
            story.append(Paragraph(location_text, self.styles["Normal"]))

        # Fix suggestions
        if issue.fix_suggestions:
            story.append(Paragraph("<b>Recommended Fixes:</b>", self.styles["Normal"]))
            for fix in issue.fix_suggestions:
                # Check if it looks like code
                if any(char in fix for char in ["<", ">", "{", "}", ":", ";"]):
                    story.append(
                        Paragraph(f"<pre>{fix}</pre>", self.styles["CodeStyle"])
                    )
                else:
                    story.append(Paragraph(f"• {fix}", self.styles["Normal"]))

        story.append(Spacer(1, 0.15 * inch))
        return story

    def _build_recommendations(self, report: ComprehensiveAnalysisReport) -> list[Any]:
        """Build recommendations and action items section."""
        story = []

        story.append(
            Paragraph("Recommendations & Action Plan", self.styles["ExecutiveHeader"])
        )

        # Use LLM-generated recommendations if available
        if self.llm_results.get("success") and self.llm_results.get("analysis"):
            # Extract specific sections from LLM analysis
            llm_analysis = self.llm_results["analysis"]

            # Critical Issues section
            critical_section = self._extract_section_from_llm(
                llm_analysis, "Critical Issues"
            )
            if critical_section:
                story.append(
                    Paragraph(
                        "🚨 AI-Identified Critical Issues", self.styles["Heading2"]
                    )
                )
                cleaned_critical = self._clean_llm_text_for_pdf(critical_section)
                story.append(Paragraph(cleaned_critical, self.styles["Normal"]))
                story.append(Spacer(1, 0.3 * inch))

            # Technical Fixes section
            fixes_section = self._extract_section_from_llm(
                llm_analysis, "Technical Fixes"
            )
            if fixes_section:
                story.append(
                    Paragraph("🔧 Specific Technical Fixes", self.styles["Heading2"])
                )
                cleaned_fixes = self._clean_llm_text_for_pdf(fixes_section)
                story.append(Paragraph(cleaned_fixes, self.styles["Normal"]))
                story.append(Spacer(1, 0.3 * inch))

            # Quick Wins section
            quick_wins_section = self._extract_section_from_llm(
                llm_analysis, "Quick Wins"
            )
            if quick_wins_section:
                story.append(
                    Paragraph(
                        "⚡ Quick Wins (Copy-Paste Ready)", self.styles["Heading2"]
                    )
                )
                cleaned_wins = self._clean_llm_text_for_pdf(quick_wins_section)
                story.append(Paragraph(cleaned_wins, self.styles["CodeStyle"]))
                story.append(Spacer(1, 0.3 * inch))

            # Implementation Guide section
            impl_section = self._extract_section_from_llm(
                llm_analysis, "Implementation Guide"
            )
            if impl_section:
                story.append(
                    Paragraph("📋 Step-by-Step Implementation", self.styles["Heading2"])
                )
                cleaned_impl = self._clean_llm_text_for_pdf(impl_section)
                story.append(Paragraph(cleaned_impl, self.styles["Normal"]))
                story.append(Spacer(1, 0.3 * inch))

        # Priority actions from LLM or fallback
        priority_actions = self.llm_results.get(
            "priority_actions", report.priority_actions or []
        )
        if priority_actions:
            story.append(
                Paragraph("Immediate Priority Actions", self.styles["Heading2"])
            )
            for i, action in enumerate(priority_actions, 1):
                story.append(Paragraph(f"{i}. {action}", self.styles["Normal"]))
            story.append(Spacer(1, 0.3 * inch))

        # Top recommendations from LLM or fallback
        recommendations = self.llm_results.get(
            "recommendations", report.top_recommendations or []
        )
        if recommendations:
            story.append(
                Paragraph("Strategic Recommendations", self.styles["Heading2"])
            )
            for i, rec in enumerate(recommendations, 1):
                story.append(Paragraph(f"{i}. {rec}", self.styles["Normal"]))
            story.append(Spacer(1, 0.3 * inch))

        return story

    def _categorize_priority(self, category: str, count: int) -> str:
        """Categorize priority level based on category and count."""
        if category.lower() == "security" and count > 0:
            return "Critical"
        elif count > 5:
            return "High"
        elif count > 2:
            return "Medium"
        else:
            return "Low"

    def _extract_section_from_llm(self, llm_analysis: str, section_name: str) -> str:
        """Extract a specific section from LLM analysis text."""
        if not llm_analysis:
            return ""

        lines = llm_analysis.split("\n")
        section_lines = []
        in_section = False

        for line in lines:
            # Check if this line starts a new section
            if line.strip().startswith("##") and section_name.lower() in line.lower():
                in_section = True
                continue
            elif line.strip().startswith("##") and in_section:
                # Hit next section, stop collecting
                break
            elif in_section:
                section_lines.append(line)

        return "\n".join(section_lines).strip()

    def _clean_llm_text_for_pdf(self, text: str) -> str:
        """Clean LLM-generated text for PDF display."""
        if not text:
            return ""

        # Remove dangerous content that could break PDF parsing
        import re

        # Remove markdown code blocks (```...```)
        cleaned = re.sub(r"```[\s\S]*?```", "[Code block removed for PDF]", text)

        # Remove inline code (`...`)
        cleaned = re.sub(r"`([^`]+)`", r"<i>\1</i>", cleaned)

        # Convert markdown bold to HTML (but be careful about nesting)
        cleaned = re.sub(r"\*\*([^*]+)\*\*", r"<b>\1</b>", cleaned)

        # Convert single asterisk to italic (but avoid double conversion)
        cleaned = re.sub(r"(?<!\*)\*([^*]+)\*(?!\*)", r"<i>\1</i>", cleaned)

        # Convert bullet points
        cleaned = cleaned.replace("- ", "• ")

        # Remove any remaining backticks or problematic characters
        cleaned = cleaned.replace("`", "'")
        cleaned = cleaned.replace("<", "&lt;").replace(">", "&gt;")

        # Restore our intended HTML tags
        cleaned = cleaned.replace("&lt;b&gt;", "<b>").replace("&lt;/b&gt;", "</b>")
        cleaned = cleaned.replace("&lt;i&gt;", "<i>").replace("&lt;/i&gt;", "</i>")
        cleaned = cleaned.replace("&lt;br/&gt;", "<br/>")

        # Remove extra whitespace and join lines
        lines = [line.strip() for line in cleaned.split("\n") if line.strip()]
        result = "<br/>".join(lines)

        # Final cleanup of malformed tags
        result = result.replace("<b><b>", "<b>").replace("</b></b>", "</b>")
        result = result.replace("<i><i>", "<i>").replace("</i></i>", "</i>")

        # Ensure no unclosed tags
        result = re.sub(r"<b>([^<]*?)(?=<b>|$)", r"<b>\1</b>", result)
        result = re.sub(r"<i>([^<]*?)(?=<i>|$)", r"<i>\1</i>", result)

        return result
