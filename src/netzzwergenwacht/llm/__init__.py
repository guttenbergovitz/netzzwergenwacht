"""LLM integration for enhanced analysis and reporting."""

import json
import os
from dataclasses import asdict
from pathlib import Path
from typing import Any

from openai import AsyncOpenAI

from ..config import config as config
from ..dwarfs.base import ComprehensiveAnalysisReport
from ..utils.logging import get_logger

logger = get_logger("llm")


class LLMError(Exception):
    """Base exception for LLM processing errors."""


class LLMProcessor:
    """Processes analysis results using LLMs for enhanced insights."""

    def __init__(self, model: str = "gpt-4o-mini"):
        self.model = model
        self.api_key = os.getenv("OPENAI_API_KEY")
        if not self.api_key:
            logger.warning("OPENAI_API_KEY not set. LLM features will be disabled.")
            raise ValueError("OPENAI_API_KEY environment variable not set")

        self.client = AsyncOpenAI(api_key=self.api_key)
        self.timeout = 30.0

    async def analyze_report(
        self, report: ComprehensiveAnalysisReport
    ) -> dict[str, Any]:
        """Process a comprehensive report with LLM to generate insights."""
        if not self.api_key:
            raise LLMError("OPENAI_API_KEY environment variable not set")

        report_summary = self._prepare_report_summary(report)

        try:
            response = await self.client.chat.completions.create(
                model=self.model,
                messages=[
                    {"role": "system", "content": self._get_system_prompt()},
                    {
                        "role": "user",
                        "content": f"Please analyze this website quality report:\n\n{json.dumps(report_summary, indent=2)}",
                    },
                ],
                temperature=0.2,
                max_tokens=2000,
            )

            analysis_text = response.choices[0].message.content

            return {
                "model": self.model,
                "analysis": analysis_text,
                "summary": self._generate_summary(report),
                "recommendations": self._extract_recommendations(analysis_text, report),
                "priority_actions": self._extract_priority_actions(
                    analysis_text, report
                ),
            }

        except Exception as e:
            logger.error(f"LLM processing failed: {str(e)}")
            # Fallback to basic analysis
            return {
                "model": "fallback",
                "analysis": f"LLM analysis failed: {str(e)}",
                "summary": self._generate_summary(report),
                "recommendations": self._generate_recommendations(report),
                "priority_actions": self._generate_priority_actions(report),
            }

    def _prepare_report_summary(
        self, report: ComprehensiveAnalysisReport
    ) -> dict[str, Any]:
        """Prepare a concise report summary for LLM consumption."""
        # Extract key insights from each dwarf
        dwarf_summaries = []
        for result in report.dwarf_results:
            if not result.success:
                continue

            critical_issues = [
                i for i in result.detailed_issues if i.severity.value == "critical"
            ]
            high_issues = [
                i for i in result.detailed_issues if i.severity.value == "high"
            ]

            dwarf_summaries.append({
                "dwarf": result.dwarf_name,
                "total_issues": len(result.detailed_issues),
                "critical_issues": len(critical_issues),
                "high_issues": len(high_issues),
                "top_critical_issues": [
                    {
                        "type": issue.issue_type,
                        "message": issue.message,
                        "impact": issue.impact,
                        "priority": issue.priority_score,
                    }
                    for issue in critical_issues[:3]
                ],
                "top_high_issues": [
                    {
                        "type": issue.issue_type,
                        "message": issue.message,
                        "impact": issue.impact,
                        "priority": issue.priority_score,
                    }
                    for issue in high_issues[:2]
                ],
            })

        return {
            "url": report.url,
            "overall_score": report.overall_score,
            "total_issues": report.total_issues,
            "critical_issues": report.critical_issues,
            "high_issues": report.high_issues,
            "medium_issues": report.medium_issues,
            "low_issues": report.low_issues,
            "issues_by_category": report.issues_by_category,
            "dwarf_analysis": dwarf_summaries,
        }

    def _get_system_prompt(self) -> str:
        """Get the system prompt for the LLM."""
        return """You are a senior web quality analyst with expertise in website performance, security, accessibility, and SEO.

Analyze the provided website quality report and provide:

1. **Executive Summary** (2-3 sentences): Overall website quality assessment
2. **Critical Actions** (max 3): Most urgent issues requiring immediate attention
3. **Recommendations** (max 5): Prioritized improvements with business impact
4. **Technical Insights** (2-3 key findings): Important technical observations

Focus on:
- Business impact of issues
- Actionable, specific recommendations
- Prioritization based on severity and user impact
- Clear, non-technical language for stakeholders

Format your response as structured text, not JSON."""

    def _extract_recommendations(
        self, analysis: str, report: ComprehensiveAnalysisReport
    ) -> list[str]:
        """Extract recommendations from LLM analysis."""
        recommendations = []

        # Look for recommendation patterns in the analysis
        lines = analysis.split("\n")
        in_recommendations = False

        for line in lines:
            line = line.strip()
            if "recommendation" in line.lower() and ":" in line:
                in_recommendations = True
                continue
            if (
                in_recommendations
                and line
                and (line.startswith(("-", "•")) or (line and line[0].isdigit()))
            ):
                rec = line.lstrip("- •0123456789.").strip()
                if rec and len(rec) > 10:  # Filter out too short recommendations
                    recommendations.append(rec)
            elif in_recommendations and line and not line.startswith(" "):
                in_recommendations = False

        # Fallback to basic recommendations if none extracted
        if not recommendations:
            recommendations = self._generate_recommendations(report)

        return recommendations[:5]  # Limit to top 5

    def _extract_priority_actions(
        self, analysis: str, report: ComprehensiveAnalysisReport
    ) -> list[str]:
        """Extract priority actions from LLM analysis."""
        actions = []

        lines = analysis.split("\n")
        in_actions = False

        for line in lines:
            line = line.strip()
            if (
                "critical" in line.lower()
                or "priority" in line.lower()
                or "urgent" in line.lower()
            ) and ":" in line:
                in_actions = True
                continue
            if (
                in_actions
                and line
                and (line.startswith(("-", "•")) or (line and line[0].isdigit()))
            ):
                action = line.lstrip("- •0123456789.").strip()
                if action and len(action) > 10:
                    actions.append(action)
            elif in_actions and line and not line.startswith(" "):
                in_actions = False

        # Fallback to basic priority actions
        if not actions:
            actions = self._generate_priority_actions(report)

        return actions[:3]  # Limit to top 3

    def _generate_summary(self, report: ComprehensiveAnalysisReport) -> str:
        """Generate a fallback summary if LLM fails."""
        summary = f"Analysis of {report.url} completed in {report.analysis_duration_seconds:.1f}s.\n"
        summary += f"Found {report.total_issues} total issues: "
        summary += f"{report.critical_issues} critical, {report.high_issues} high, "
        summary += f"{report.medium_issues} medium, {report.low_issues} low.\n"

        if report.overall_score:
            score_category = (
                "excellent"
                if report.overall_score >= 80
                else "good"
                if report.overall_score >= 60
                else "needs improvement"
            )
            summary += f"Overall quality score: {report.overall_score:.1f}/100 ({score_category})."

        return summary

    def _generate_recommendations(
        self, report: ComprehensiveAnalysisReport
    ) -> list[str]:
        """Generate fallback recommendations if LLM fails."""
        recs = []

        # Get top issues by priority
        all_issues = []
        for result in report.dwarf_results:
            all_issues.extend(result.detailed_issues)

        top_issues = sorted(all_issues, key=lambda x: x.priority_score, reverse=True)[
            :5
        ]

        for issue in top_issues:
            if issue.recommendations:
                recs.extend(
                    issue.recommendations[:1]
                )  # Take first recommendation per issue
            elif issue.fix_suggestions:
                recs.extend(issue.fix_suggestions[:1])  # Take first fix suggestion

        return list(set(recs[:5]))  # Remove duplicates and limit to 5

    def _generate_priority_actions(
        self, report: ComprehensiveAnalysisReport
    ) -> list[str]:
        """Generate priority actions based on critical issues."""
        actions = []

        for result in report.dwarf_results:
            critical_issues = [
                i for i in result.detailed_issues if i.severity.value == "critical"
            ]
            for issue in critical_issues[:1]:  # Take top critical issue per dwarf
                if issue.fix_suggestions:
                    actions.append(f"[{result.dwarf_name}] {issue.fix_suggestions[0]}")
                else:
                    actions.append(
                        f"[{result.dwarf_name}] Address {issue.issue_type.replace('_', ' ')}"
                    )

        return actions[:3]

    def save_for_llm(self, report: ComprehensiveAnalysisReport, path: Path) -> None:
        """Save report in LLM-friendly JSON format."""
        path.parent.mkdir(parents=True, exist_ok=True)

        # Create comprehensive LLM-ready data
        llm_data = {
            "metadata": {
                "url": report.url,
                "timestamp": report.timestamp.isoformat() if report.timestamp else None,
                "analysis_duration": report.analysis_duration_seconds,
                "overall_score": report.overall_score,
            },
            "summary": {
                "total_issues": report.total_issues,
                "critical_issues": report.critical_issues,
                "high_issues": report.high_issues,
                "medium_issues": report.medium_issues,
                "low_issues": report.low_issues,
                "issues_by_category": report.issues_by_category,
            },
            "dwarf_results": [],
            "llm_ready_summary": self._prepare_report_summary(report),
        }

        # Add detailed dwarf results
        for result in report.dwarf_results:
            dwarf_data = {
                "dwarf_name": result.dwarf_name,
                "success": result.success,
                "error_message": result.error_message,
                "issues_count": len(result.detailed_issues),
                "detailed_issues": [asdict(issue) for issue in result.detailed_issues],
            }

            # Add metrics if available
            if hasattr(result, "performance_metrics") and result.performance_metrics:
                dwarf_data["performance_metrics"] = asdict(result.performance_metrics)
            if hasattr(result, "security_metrics") and result.security_metrics:
                dwarf_data["security_metrics"] = asdict(result.security_metrics)
            if (
                hasattr(result, "accessibility_metrics")
                and result.accessibility_metrics
            ):
                dwarf_data["accessibility_metrics"] = asdict(
                    result.accessibility_metrics
                )
            if hasattr(result, "seo_metrics") and result.seo_metrics:
                dwarf_data["seo_metrics"] = asdict(result.seo_metrics)
            if hasattr(result, "content_metrics") and result.content_metrics:
                dwarf_data["content_metrics"] = asdict(result.content_metrics)
            if hasattr(result, "visual_metrics") and result.visual_metrics:
                dwarf_data["visual_metrics"] = asdict(result.visual_metrics)

            llm_data["dwarf_results"].append(dwarf_data)

        with open(path, "w", encoding="utf-8") as f:
            json.dump(llm_data, f, indent=2, ensure_ascii=False, default=str)
