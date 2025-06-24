"""LLM integration for enhanced analysis and reporting."""

import os
from typing import Any, Optional
from dataclasses import asdict
import json
from pathlib import Path
import httpx

from ..config import config
from ..dwarfs.base import ComprehensiveAnalysisReport
from ..utils.logging import get_logger

logger = get_logger("llm")

class LLMError(Exception):
    """Base exception for LLM processing errors."""
    pass

class LLMProcessor:
    """Processes analysis results using LLMs for enhanced insights."""
    
    def __init__(self, model: str = "gpt-4-turbo"):
        self.model = model
        self.api_key = os.getenv("OPENAI_API_KEY")
        if not self.api_key:
            raise ValueError("OPENAI_API_KEY environment variable not set")
        self.base_url = "https://api.openai.com/v1"
        self.timeout = 30.0
        
    async def analyze_report(self, report: ComprehensiveAnalysisReport) -> dict[str, Any]:
        """Process a comprehensive report with LLM to generate insights."""
        if not self.api_key:
            raise LLMError("OPENAI_API_KEY environment variable not set")
            
        report_dict = self._prepare_report_data(report)
        
        try:
            async with httpx.AsyncClient(timeout=self.timeout) as client:
                response = await client.post(
                    f"{self.base_url}/chat/completions",
                    headers={
                        "Authorization": f"Bearer {self.api_key}",
                        "Content-Type": "application/json"
                    },
                    json={
                        "model": self.model,
                        "messages": [
                            {
                                "role": "system",
                                "content": self._get_system_prompt()
                            },
                            {
                                "role": "user",
                                "content": json.dumps(report_dict, ensure_ascii=False)
                            }
                        ],
                        "temperature": 0.2,
                        "max_tokens": 2000
                    }
                )
                
                if response.status_code != 200:
                    raise LLMError(f"API request failed: {response.text}")
                    
                result = response.json()
                return self._process_llm_response(result, report)
                
        except Exception as e:
            logger.error(f"LLM processing failed: {str(e)}")
            raise LLMError(f"LLM processing failed: {str(e)}") from e
            
    def _prepare_report_data(self, report: ComprehensiveAnalysisReport) -> dict[str, Any]:
        """Prepare the report data for LLM consumption."""
        report_dict = asdict(report)
        
        # Simplify complex structures
        for result in report_dict.get("dwarf_results", []):
            result["detailed_issues"] = [
                {k: v for k, v in issue.items() 
                 if k in ["issue_type", "severity", "message", "priority_score"]}
                for issue in result["detailed_issues"]
            ]
            
        return {
            "url": report_dict["url"],
            "overall_score": report_dict.get("overall_score"),
            "critical_issues": report_dict["critical_issues"],
            "high_issues": report_dict["high_issues"],
            "dwarf_summaries": [
                {
                    "dwarf_name": r["dwarf_name"],
                    "issues_count": len(r["detailed_issues"]),
                    "top_issues": r["detailed_issues"][:3]
                }
                for r in report_dict["dwarf_results"]
            ]
        }
        
    def _get_system_prompt(self) -> str:
        """Get the system prompt for the LLM."""
        return """You are a senior web quality analyst. Analyze the provided website 
        quality report and provide:
        1. A concise executive summary
        2. Prioritized recommendations
        3. Key technical findings
        
        Focus on critical and high severity issues first. 
        Provide specific, actionable recommendations."""
        
    def _process_llm_response(self, response: dict, report: ComprehensiveAnalysisReport) -> dict[str, Any]:
        """Process the raw LLM API response."""
        content = response["choices"][0]["message"]["content"]
        
        try:
            # Try to parse as JSON if possible
            llm_data = json.loads(content)
        except json.JSONDecodeError:
            # Fall back to plain text
            llm_data = {"analysis": content}
            
        return {
            "model": self.model,
            "analysis": llm_data,
            "summary": self._generate_summary(report),
            "recommendations": self._generate_recommendations(report),
            "raw_response": response
        }
        
    def _generate_summary(self, report: ComprehensiveAnalysisReport) -> str:
        """Generate a fallback summary if LLM fails."""
        summary = f"Analysis of {report.url} found {report.total_issues} issues:\n"
        summary += f"- Critical: {report.critical_issues}\n"
        summary += f"- High: {report.high_issues}\n" 
        summary += f"- Medium: {report.medium_issues}\n"
        summary += f"- Low: {report.low_issues}\n"
        
        if report.overall_score:
            summary += f"\nOverall Quality Score: {report.overall_score:.1f}/100\n"
            
        return summary
        
    def _generate_recommendations(self, report: ComprehensiveAnalysisReport) -> list[str]:
        """Generate fallback recommendations if LLM fails."""
        recs = []
        
        for issue in sorted(
            (i for r in report.dwarf_results for i in r.detailed_issues),
            key=lambda x: x.priority_score,
            reverse=True
        ):
            if issue.severity.value in ("critical", "high"):
                recs.append(f"{issue.message} (Priority: {issue.priority_score:.1f})")
                
        return recs[:5]  # Return top 5
        
    def save_for_llm(self, report: ComprehensiveAnalysisReport, path: Path) -> None:
        """Save report in LLM-friendly JSON format."""
        path.parent.mkdir(parents=True, exist_ok=True)
        with open(path, "w", encoding="utf-8") as f:
            json.dump({
                "report": asdict(report),
                "llm_ready": self._prepare_report_data(report)
            }, f, indent=2, ensure_ascii=False)
