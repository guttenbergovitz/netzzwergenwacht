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

        # Enhanced logging about LLM setup
        if not self.api_key:
            logger.warning("🔑 OPENAI_API_KEY not found in environment variables")
            logger.info(
                "💡 To enable LLM features, set: export OPENAI_API_KEY='your-key-here'"
            )
            raise ValueError("OPENAI_API_KEY environment variable not set")

        # Mask API key for logging (show only first 8 chars)
        masked_key = f"{self.api_key[:8]}..." if len(self.api_key) > 8 else "***"
        logger.info(f"🤖 LLM initialized with model: {self.model}")
        logger.info(f"🔑 Using OpenAI API key: {masked_key}")

        self.client = AsyncOpenAI(api_key=self.api_key)
        self.timeout = 30.0

        # Estimate costs per token for the model
        self.cost_per_1k_input_tokens = self._get_model_costs()[0]
        self.cost_per_1k_output_tokens = self._get_model_costs()[1]

    async def analyze_report(
        self, report: ComprehensiveAnalysisReport
    ) -> dict[str, Any]:
        """Process a comprehensive report with LLM to generate insights."""
        if not self.api_key:
            raise LLMError("OPENAI_API_KEY environment variable not set")

        report_summary = self._prepare_report_summary(report)

        # Calculate input tokens (rough estimation)
        input_text = self._get_system_prompt() + json.dumps(report_summary)
        estimated_input_tokens = len(input_text.split()) * 1.3  # rough estimation

        logger.info(f"📊 Sending request to {self.model}")
        logger.info(f"📝 Estimated input tokens: ~{estimated_input_tokens:.0f}")
        logger.info(
            f"💰 Estimated input cost: ~${estimated_input_tokens * self.cost_per_1k_input_tokens / 1000:.4f}"
        )

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
                max_tokens=3000,  # Increased for more detailed output
            )

            # Log actual usage
            usage = response.usage
            logger.info("✅ LLM request completed successfully")
            logger.info(
                f"📊 Token usage - Input: {usage.prompt_tokens}, Output: {usage.completion_tokens}, Total: {usage.total_tokens}"
            )

            input_cost = usage.prompt_tokens * self.cost_per_1k_input_tokens / 1000
            output_cost = (
                usage.completion_tokens * self.cost_per_1k_output_tokens / 1000
            )
            total_cost = input_cost + output_cost

            logger.info(
                f"💰 Actual cost - Input: ${input_cost:.4f}, Output: ${output_cost:.4f}, Total: ${total_cost:.4f}"
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
                "usage": {
                    "input_tokens": usage.prompt_tokens,
                    "output_tokens": usage.completion_tokens,
                    "total_tokens": usage.total_tokens,
                    "cost": total_cost,
                },
                "success": True,
            }

        except Exception as e:
            logger.error(f"❌ LLM processing failed: {str(e)}")
            logger.info("🔄 Falling back to basic analysis without LLM")
            # Fallback to basic analysis
            return {
                "model": "fallback",
                "analysis": f"LLM analysis failed: {str(e)}",
                "summary": self._generate_summary(report),
                "recommendations": self._generate_recommendations(report),
                "priority_actions": self._generate_priority_actions(report),
                "success": False,
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

Analyze the provided website quality report and provide a comprehensive analysis with the following sections:

## 1. Executive Summary
Provide a 3-4 sentence overview of the website's overall quality, highlighting the most significant findings and the overall quality level.

## 2. Critical Issues Requiring Immediate Attention
List the 3 most urgent issues that need immediate action, explaining:
- What the problem is
- Why it's critical for business/users
- Immediate impact if not fixed

## 3. Priority Recommendations
Provide 5-7 prioritized recommendations with:
- Clear action items
- Expected business impact
- Estimated effort level (Low/Medium/High)
- Timeline recommendation (Immediate/Short-term/Medium-term)

## 4. Technical Analysis by Category
Break down findings by:
- **Performance**: Load times, Core Web Vitals, optimization opportunities
- **Security**: Vulnerabilities, SSL issues, headers, exposures
- **Accessibility**: WCAG compliance, mobile usability, user experience
- **SEO & Content**: Search optimization, content quality, structure
- **Visual & UX**: Design consistency, layout issues, user interface

## 5. Business Impact Assessment
Explain how the identified issues affect:
- User experience and conversion rates
- Search engine rankings
- Brand reputation and trust
- Potential security risks

## 6. Implementation Roadmap
Suggest a phased approach:
- **Phase 1 (Immediate - 1-2 weeks)**: Critical fixes
- **Phase 2 (Short-term - 1 month)**: High-impact improvements
- **Phase 3 (Medium-term - 2-3 months)**: Long-term optimizations

Focus on actionable insights that developers and business stakeholders can understand and act upon."""

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

    def _get_model_costs(self) -> tuple[float, float]:
        """Get cost per 1K tokens for input and output for the current model.

        Returns:
            Tuple of (input_cost_per_1k, output_cost_per_1k) in USD
        """
        # Pricing as of December 2024 (in USD per 1K tokens)
        model_costs = {
            "gpt-4o-mini": (0.00015, 0.0006),  # Very economical
            "gpt-4o": (0.0025, 0.01),  # More powerful but expensive
            "gpt-4-turbo": (0.01, 0.03),  # Previous generation
            "gpt-3.5-turbo": (0.0005, 0.0015),  # Legacy but cheap
        }

        return model_costs.get(self.model, (0.001, 0.003))  # Default fallback

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
