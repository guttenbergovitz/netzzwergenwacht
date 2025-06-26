"""CrewAI orchestrator for multi-agent web analysis."""

import os
from typing import Any

from crewai import Agent, Crew, Task
from crewai.agent import BaseAgent
from langchain_openai import ChatOpenAI

from ..dwarfs.base import ComprehensiveAnalysisReport
from ..utils.logging import get_logger
from .accessibility_agent import AccessibilityExpertAgent
from .content_agent import ContentExpertAgent
from .monitoring_agent import MonitoringExpertAgent
from .performance_agent import PerformanceExpertAgent
from .reporting_agent import ReportingExpertAgent
from .rule_engine_agent import RuleEngineExpertAgent
from .security_agent import SecurityExpertAgent
from .seo_agent import SEOExpertAgent
from .visual_agent import VisualExpertAgent
from .web_browser_agent import WebBrowserExpertAgent

logger = get_logger("crew_orchestrator")


class WebAnalysisCrew:
    """Orchestrates multiple specialist agents for comprehensive web analysis."""

    def __init__(self, model: str = "gpt-4o-mini", temperature: float = 0.2):
        """Initialize the crew with LLM configuration."""
        self.api_key = os.getenv("OPENAI_API_KEY")
        if not self.api_key:
            raise ValueError("OPENAI_API_KEY environment variable not set")

        self.llm = ChatOpenAI(
            model=model,
            temperature=temperature,
            api_key=self.api_key,  # type: ignore
        )

        self.agents: list[BaseAgent] = []
        self.tasks: list[Task] = []
        self.crew: Crew | None = None

        logger.info(f"🤖 CrewAI initialized with model: {model}")

    def create_agents(self) -> None:
        """Create specialized expert agents."""

        # Security Expert Agent
        security_agent_instance = SecurityExpertAgent(llm=self.llm)
        security_agent = security_agent_instance.create_agent()

        # Performance Expert Agent
        performance_agent_instance = PerformanceExpertAgent(llm=self.llm)
        performance_agent = performance_agent_instance.create_agent()

        # Accessibility Expert Agent
        accessibility_agent_instance = AccessibilityExpertAgent(llm=self.llm)
        accessibility_agent = accessibility_agent_instance.create_agent()

        # SEO Expert Agent
        seo_agent_instance = SEOExpertAgent(llm=self.llm)
        seo_agent = seo_agent_instance.create_agent()

        # Content Expert Agent
        content_agent_instance = ContentExpertAgent(llm=self.llm)
        content_agent = content_agent_instance.create_agent()

        # Visual Expert Agent
        visual_agent_instance = VisualExpertAgent(llm=self.llm)
        visual_agent = visual_agent_instance.create_agent()

        # Web Browser Expert Agent
        web_browser_agent_instance = WebBrowserExpertAgent(llm=self.llm)
        web_browser_agent = web_browser_agent_instance.create_agent()

        # Reporting Expert Agent
        reporting_agent_instance = ReportingExpertAgent(llm=self.llm)
        reporting_agent = reporting_agent_instance.create_agent()

        # Monitoring Expert Agent
        monitoring_agent_instance = MonitoringExpertAgent(llm=self.llm)
        monitoring_agent = monitoring_agent_instance.create_agent()

        # Rule Engine Expert Agent
        rule_engine_agent_instance = RuleEngineExpertAgent(llm=self.llm)
        rule_engine_agent = rule_engine_agent_instance.create_agent()

        # Analysis Coordinator Agent
        coordinator_agent = Agent(
            role="Senior Website Analysis Coordinator",
            goal="Synthesize expert findings into a comprehensive, prioritized action plan",
            backstory="""You are a technical lead with expertise across security, performance,
            and accessibility domains. You excel at correlating issues across different areas,
            identifying root causes, and creating prioritized remediation roadmaps.
            You understand business impact and can translate technical findings into executive summaries.""",
            llm=self.llm,
            verbose=True,
            allow_delegation=False,
            max_iter=5,
        )

        self.agents = [
            security_agent,
            performance_agent,
            accessibility_agent,
            seo_agent,
            content_agent,
            visual_agent,
            web_browser_agent,
            reporting_agent,
            monitoring_agent,
            rule_engine_agent,
            coordinator_agent,
        ]
        logger.info(f"✅ Created {len(self.agents)} specialist agents")

    def create_tasks(self, report_data: dict[str, Any]) -> None:
        """Create analysis tasks for each agent."""

        # Security Analysis Task
        security_task = Task(
            description=f"""
            Analyze the security findings from this website analysis:

            Security Issues: {report_data.get("security_issues", [])}
            Security Metrics: {report_data.get("security_metrics", {})}
            URL: {report_data.get("url", "N/A")}

            Your analysis should:
            1. Prioritize security issues by severity and business impact
            2. Identify potential attack vectors and exploitation scenarios
            3. Provide specific remediation steps with exact code/configuration examples
            4. Estimate implementation effort and timeline
            5. Correlate related security issues to identify root causes

            Focus on actionable, copy-paste ready solutions.
            """,
            agent=self.agents[0],  # Security agent
            expected_output="Detailed security analysis with prioritized remediation plan",
        )

        # Performance Analysis Task
        performance_task = Task(
            description=f"""
            Analyze the performance findings from this website analysis:

            Performance Issues: {report_data.get("performance_issues", [])}
            Performance Metrics: {report_data.get("performance_metrics", {})}
            Core Web Vitals: {report_data.get("core_web_vitals", {})}
            URL: {report_data.get("url", "N/A")}

            Your analysis should:
            1. Identify performance bottlenecks and their root causes.
            2. Correlate performance issues with user experience impact.
            3. Provide specific optimization strategies with expected improvements.
            4. Prioritize optimizations by impact vs effort ratio.
            5. Include code examples and configuration changes.

            Focus on measurable performance improvements.
            """,
            agent=self.agents[1],  # Performance agent
            expected_output="Comprehensive performance optimization roadmap",
        )

        # Accessibility Analysis Task
        accessibility_task = Task(
            description=f"""
            Analyze the accessibility findings from this website analysis:

            Accessibility Issues: {report_data.get("accessibility_issues", [])}
            Accessibility Metrics: {report_data.get("accessibility_metrics", {})}
            URL: {report_data.get("url", "N/A")}

            Your analysis should:
            1. Assess WCAG 2.1 AA compliance gaps.
            2. Identify barriers for users with disabilities.
            3. Provide specific ARIA and HTML remediation strategies.
            4. Prioritize fixes by user impact and implementation complexity.
            5. Include code examples for accessibility improvements.

            Focus on inclusive design and assistive technology compatibility.
            """,
            agent=self.agents[2],  # Accessibility agent
            expected_output="Detailed accessibility compliance roadmap",
        )

        # SEO Analysis Task
        seo_task = Task(
            description=f"""
            Analyze the SEO findings from this website analysis:

            SEO Issues: {report_data.get("seo_issues", [])}
            SEO Metrics: {report_data.get("seo_metrics", {})}
            URL: {report_data.get("url", "N/A")}

            Your analysis should:
            1. Identify critical SEO issues and opportunities.
            2. Provide specific on-page and technical SEO recommendations.
            3. Suggest content optimization strategies.
            4. Prioritize SEO improvements by potential impact on organic traffic.
            5. Include examples for meta tags, heading structure, and structured data.

            Focus on improving search engine visibility and ranking.
            """,
            agent=self.agents[3],  # SEO agent
            expected_output="Detailed SEO analysis with prioritized optimization strategies",
        )

        # Content Analysis Task
        content_task = Task(
            description=f"""
            Analyze the content findings from this website analysis:

            Content Issues: {report_data.get("content_issues", [])}
            Content Metrics: {report_data.get("content_metrics", {})}
            URL: {report_data.get("url", "N/A")}

            Your analysis should:
            1. Assess content quality, readability, and freshness.
            2. Identify duplicate content and structural issues.
            3. Provide recommendations for improving language quality and user engagement.
            4. Suggest content formatting and heading structure improvements.

            Focus on enhancing the overall quality and effectiveness of the website's content.
            """,
            agent=self.agents[4],  # Content agent
            expected_output="Detailed content analysis with recommendations for quality and readability",
        )

        # Visual Analysis Task
        visual_task = Task(
            description=f"""
            Analyze the visual findings from this website analysis:

            Visual Issues: {report_data.get("visual_issues", [])}
            Visual Metrics: {report_data.get("visual_metrics", {})}
            URL: {report_data.get("url", "N/A")}

            Your analysis should:
            1. Assess visual consistency, UI element detection, and layout issues.
            2. Provide recommendations for improving color schemes, typography, and overall visual appeal.
            3. Identify and suggest fixes for overlapping elements, overflow problems, and responsive design issues.

            Focus on enhancing the visual quality and user experience of the website.
            """,
            agent=self.agents[5],  # Visual agent
            expected_output="Detailed visual analysis with recommendations for design and UI/UX improvements",
        )

        # Web Browser Analysis Task
        web_browser_task = Task(
            description=f"""
            Analyze the web browser findings from this website analysis:

            Web Browser Issues: {report_data.get("web_browser_issues", [])}
            Web Browser Metrics: {report_data.get("web_browser_metrics", {})}
            URL: {report_data.get("url", "N/A")}

            Your analysis should:
            1. Identify HTTP status issues, redirects, and response time problems.
            2. Analyze HTML structure, JavaScript console errors, and network request failures.
            3. Provide recommendations for improving basic SEO attributes and browser-based accessibility.

            Focus on ensuring the website functions correctly and efficiently across different browsers.
            """,
            agent=self.agents[6],  # Web Browser agent
            expected_output="Detailed web browser analysis with recommendations for functionality and efficiency",
        )

        # Reporting Analysis Task
        reporting_task = Task(
            description=f"""
            Generate a comprehensive report based on the following analysis findings:

            Security Analysis: {report_data.get("security_issues", [])}
            Performance Analysis: {report_data.get("performance_issues", [])}
            Accessibility Analysis: {report_data.get("accessibility_issues", [])}
            SEO Analysis: {report_data.get("seo_issues", [])}
            Content Analysis: {report_data.get("content_issues", [])}
            Visual Analysis: {report_data.get("visual_issues", [])}
            Web Browser Analysis: {report_data.get("web_browser_issues", [])}
            URL: {report_data.get("url", "N/A")}

            Your report should:
            1. Provide an executive summary highlighting key findings and overall website quality.
            2. Include detailed sections for each analysis area (Security, Performance, etc.) with prioritized issues.
            3. Offer actionable recommendations and specific fix suggestions with code examples where applicable.
            4. Present relevant metrics and their interpretation.
            5. Be structured for clarity and easy readability by both technical and non-technical stakeholders.

            Focus on creating a professional, comprehensive, and actionable report.
            """,
            agent=self.agents[7],  # Reporting agent
            expected_output="Comprehensive and actionable analysis report",
        )

        # Monitoring Analysis Task
        monitoring_task = Task(
            description=f"""
            Analyze the monitoring requirements for this website based on the analysis findings:

            Security Issues: {report_data.get("security_issues", [])}
            Performance Issues: {report_data.get("performance_issues", [])}
            Accessibility Issues: {report_data.get("accessibility_issues", [])}
            SEO Issues: {report_data.get("seo_issues", [])}
            Content Issues: {report_data.get("content_issues", [])}
            Visual Issues: {report_data.get("visual_issues", [])}
            Web Browser Issues: {report_data.get("web_browser_issues", [])}
            URL: {report_data.get("url", "N/A")}

            Your analysis should:
            1. Identify key metrics and events that need continuous monitoring.
            2. Suggest appropriate monitoring tools and configurations.
            3. Define thresholds for alerts and notifications.
            4. Propose a strategy for real-time anomaly detection.
            5. Outline a plan for integrating monitoring into existing CI/CD pipelines.

            Focus on establishing a robust and proactive monitoring system.
            """,
            agent=self.agents[8],  # Monitoring agent
            expected_output="Detailed monitoring strategy and implementation plan",
        )

        # Rule Engine Analysis Task
        rule_engine_task = Task(
            description=f"""
            Analyze the custom rule requirements for this website based on the analysis findings:

            Security Issues: {report_data.get("security_issues", [])}
            Performance Issues: {report_data.get("performance_issues", [])}
            Accessibility Issues: {report_data.get("accessibility_issues", [])}
            SEO Issues: {report_data.get("seo_issues", [])}
            Content Issues: {report_data.get("content_issues", [])}
            Visual Issues: {report_data.get("visual_issues", [])}
            Web Browser Issues: {report_data.get("web_browser_issues", [])}
            Reporting Issues: {report_data.get("reporting_issues", [])}
            Monitoring Issues: {report_data.get("monitoring_issues", [])}
            URL: {report_data.get("url", "N/A")}

            Your analysis should:
            1. Identify areas where custom rules can enhance analysis or enforce specific standards.
            2. Propose new rule definitions based on recurring patterns or unique requirements.
            3. Outline the logic and conditions for each custom rule.
            4. Suggest how these rules can be integrated into the existing analysis workflow.
            5. Consider the impact of new rules on performance and reporting.

            Focus on extending the system's analytical capabilities through custom rule sets.
            """,
            agent=self.agents[9],  # Rule Engine agent
            expected_output="Detailed custom rule definitions and integration plan",
        )

        # Coordination Task
        coordination_task = Task(
            description="""
            Synthesize the expert analyses from Security, Performance, Accessibility, SEO, Content, Visual, Web Browser, Reporting, Monitoring, and Rule Engine teams
            into a comprehensive, executive-ready action plan.

            Based on the individual expert reports, create:

            1. **Executive Summary** (2-3 sentences)
               - Overall website quality assessment
               - Key business risks and opportunities

            2. **Critical Issues Matrix**
               - Cross-cutting issues affecting multiple domains
               - Root cause analysis and correlation insights
               - Business impact prioritization

            3. **Phased Implementation Roadmap**
               - Phase 1: Critical fixes (1-2 weeks)
               - Phase 2: High-impact improvements (1-2 months)
               - Phase 3: Long-term optimizations (3-6 months)

            4. **Resource Requirements**
               - Development effort estimates
               - Required expertise/skills
               - External dependencies

            5. **Success Metrics**
               - KPIs to track improvement
               - Before/after benchmarks
               - Monitoring recommendations

            Focus on actionable insights that drive business value.
            """,
            agent=self.agents[10],  # Coordinator agent (index adjusted)
            expected_output="Executive-ready comprehensive analysis and action plan",
            context=[
                security_task,
                performance_task,
                accessibility_task,
                seo_task,
                content_task,
                visual_task,
                web_browser_task,
                reporting_task,
                monitoring_task,
                rule_engine_task,
            ],
        )

        self.tasks = [
            security_task,
            performance_task,
            accessibility_task,
            seo_task,
            content_task,
            visual_task,
            web_browser_task,
            reporting_task,
            monitoring_task,
            rule_engine_task,
            coordination_task,
        ]
        logger.info(f"✅ Created {len(self.tasks)} analysis tasks")

    def _prepare_report_data(
        self, report: ComprehensiveAnalysisReport
    ) -> dict[str, Any]:
        """Prepare report data for agent consumption."""
        data = {
            "url": report.url,
            "total_issues": report.total_issues,
            "critical_issues": report.critical_issues,
            "high_issues": report.high_issues,
            "security_issues": [],
            "performance_issues": [],
            "accessibility_issues": [],
            "seo_issues": [],
            "content_issues": [],
            "visual_issues": [],
            "web_browser_issues": [],
            "reporting_issues": [],
            "monitoring_issues": [],
            "rule_engine_issues": [],
            "security_metrics": {},
            "performance_metrics": {},
            "accessibility_metrics": {},
            "seo_metrics": {},
            "content_metrics": {},
            "visual_metrics": {},
            "web_browser_metrics": {},
            "reporting_metrics": {},
            "monitoring_metrics": {},
            "rule_engine_metrics": {},
        }

        # Extract issues by category
        for result in report.dwarf_results:
            if not result.success:
                continue

            dwarf_type = result.dwarf_name.lower()

            if "security" in dwarf_type or "sicherheits" in dwarf_type:
                data["security_issues"].extend([  # type: ignore
                    {
                        "type": issue.issue_type,
                        "severity": issue.severity.value,
                        "description": issue.description,
                        "impact": issue.impact,
                        "location": issue.location,
                        "fix_suggestions": issue.fix_suggestions,
                    }
                    for issue in result.detailed_issues
                ])
                if hasattr(result, "security_metrics") and result.security_metrics:
                    data["security_metrics"] = result.security_metrics.__dict__

            elif "performance" in dwarf_type or "leistungs" in dwarf_type:
                data["performance_issues"].extend([  # type: ignore
                    {
                        "type": issue.issue_type,
                        "severity": issue.severity.value,
                        "description": issue.description,
                        "impact": issue.impact,
                        "location": issue.location,
                        "fix_suggestions": issue.fix_suggestions,
                    }
                    for issue in result.detailed_issues
                ])
                if (
                    hasattr(result, "performance_metrics")
                    and result.performance_metrics
                ):
                    data["performance_metrics"] = result.performance_metrics.__dict__

            elif "accessibility" in dwarf_type or "zugaenglichkeits" in dwarf_type:
                data["accessibility_issues"].extend([  # type: ignore
                    {
                        "type": issue.issue_type,
                        "severity": issue.severity.value,
                        "description": issue.description,
                        "impact": issue.impact,
                        "location": issue.location,
                        "fix_suggestions": issue.fix_suggestions,
                    }
                    for issue in result.detailed_issues
                ])
                if (
                    hasattr(result, "accessibility_metrics")
                    and result.accessibility_metrics
                ):
                    data["accessibility_metrics"] = (
                        result.accessibility_metrics.__dict__
                    )
            elif "seo" in dwarf_type:
                data["seo_issues"].extend([  # type: ignore
                    {
                        "type": issue.issue_type,
                        "severity": issue.severity.value,
                        "description": issue.description,
                        "impact": issue.impact,
                        "location": issue.location,
                        "fix_suggestions": issue.fix_suggestions,
                    }
                    for issue in result.detailed_issues
                ])
                if hasattr(result, "seo_metrics") and result.seo_metrics:
                    data["seo_metrics"] = result.seo_metrics.__dict__
            elif "inhalt" in dwarf_type or "content" in dwarf_type:
                data["content_issues"].extend([  # type: ignore
                    {
                        "type": issue.issue_type,
                        "severity": issue.severity.value,
                        "description": issue.description,
                        "impact": issue.impact,
                        "location": issue.location,
                        "fix_suggestions": issue.fix_suggestions,
                    }
                    for issue in result.detailed_issues
                ])
                if hasattr(result, "content_metrics") and result.content_metrics:
                    data["content_metrics"] = result.content_metrics.__dict__
            elif "visual" in dwarf_type:
                data["visual_issues"].extend([  # type: ignore
                    {
                        "type": issue.issue_type,
                        "severity": issue.severity.value,
                        "description": issue.description,
                        "impact": issue.impact,
                        "location": issue.location,
                        "fix_suggestions": issue.fix_suggestions,
                    }
                    for issue in result.detailed_issues
                ])
                if hasattr(result, "visual_metrics") and result.visual_metrics:
                    data["visual_metrics"] = result.visual_metrics.__dict__
            elif "web_browser" in dwarf_type:
                data["web_browser_issues"].extend([  # type: ignore
                    {
                        "type": issue.issue_type,
                        "severity": issue.severity.value,
                        "description": issue.description,
                        "impact": issue.impact,
                        "location": issue.location,
                        "fix_suggestions": issue.fix_suggestions,
                    }
                    for issue in result.detailed_issues
                ])
                if (
                    hasattr(result, "web_browser_metrics")
                    and result.web_browser_metrics
                ):
                    data["web_browser_metrics"] = result.web_browser_metrics.__dict__
            elif "reporting" in dwarf_type:
                data["reporting_issues"].extend([  # type: ignore
                    {
                        "type": issue.issue_type,
                        "severity": issue.severity.value,
                        "description": issue.description,
                        "impact": issue.impact,
                        "location": issue.location,
                        "fix_suggestions": issue.fix_suggestions,
                    }
                    for issue in result.detailed_issues
                ])
                if hasattr(result, "reporting_metrics") and result.reporting_metrics:
                    data["reporting_metrics"] = result.reporting_metrics.__dict__
            elif "monitoring" in dwarf_type:
                data["monitoring_issues"].extend([  # type: ignore
                    {
                        "type": issue.issue_type,
                        "severity": issue.severity.value,
                        "description": issue.description,
                        "impact": issue.impact,
                        "location": issue.location,
                        "fix_suggestions": issue.fix_suggestions,
                    }
                    for issue in result.detailed_issues
                ])
                if hasattr(result, "monitoring_metrics") and result.monitoring_metrics:
                    data["monitoring_metrics"] = result.monitoring_metrics.__dict__
            elif "rule_engine" in dwarf_type:
                data["rule_engine_issues"].extend([  # type: ignore
                    {
                        "type": issue.issue_type,
                        "severity": issue.severity.value,
                        "description": issue.description,
                        "impact": issue.impact,
                        "location": issue.location,
                        "fix_suggestions": issue.fix_suggestions,
                    }
                    for issue in result.detailed_issues
                ])
                if (
                    hasattr(result, "rule_engine_metrics")
                    and result.rule_engine_metrics
                ):
                    data["rule_engine_metrics"] = result.rule_engine_metrics.__dict__

        return data

    def _format_crew_results(self, crew_result: Any) -> dict[str, Any]:
        """Format crew execution results."""
        return {
            "success": True,
            "model": "CrewAI Multi-Agent",
            "analysis": str(crew_result),
            "agent_count": len(self.agents),
            "task_count": len(self.tasks),
            "analysis_type": "multi_agent_collaboration",
            "agents_used": [agent.role for agent in self.agents],
        }
