"""CrewAI orchestrator for multi-agent web analysis."""

import os
from typing import Any

from crewai import Agent, Crew, Task
from crewai.agent import BaseAgent
from langchain_openai import ChatOpenAI

from ..dwarfs.base import ComprehensiveAnalysisReport
from ..utils.logging import get_logger

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
        security_agent = Agent(
            role="Senior Web Security Analyst",
            goal="Identify critical security vulnerabilities and provide actionable remediation steps",
            backstory="""You are a cybersecurity expert with 15+ years of experience in web application security.
            You specialize in OWASP Top 10, SSL/TLS security, security headers, and vulnerability assessment.
            You understand the business impact of security issues and can prioritize them effectively.
            You provide specific, actionable remediation steps with exact code examples.""",
            llm=self.llm,
            verbose=True,
            allow_delegation=False,
            max_iter=3,
        )

        # Performance Expert Agent
        performance_agent = Agent(
            role="Senior Performance Engineer",
            goal="Analyze website performance and Core Web Vitals, providing optimization strategies",
            backstory="""You are a web performance expert with deep knowledge of Core Web Vitals,
            browser rendering, network optimization, and performance budgets. You understand how
            performance impacts user experience, SEO rankings, and conversion rates.
            You provide specific optimization techniques with measurable improvements.""",
            llm=self.llm,
            verbose=True,
            allow_delegation=False,
            max_iter=3,
        )

        # Accessibility Expert Agent
        accessibility_agent = Agent(
            role="Senior Accessibility Consultant",
            goal="Ensure WCAG 2.1 AA compliance and identify accessibility barriers",
            backstory="""You are an accessibility expert certified in WCAG 2.1 AA/AAA guidelines
            and EU Accessibility Act compliance. You understand assistive technologies, screen readers,
            and inclusive design principles. You can identify accessibility barriers and provide
            specific ARIA and HTML remediation strategies.""",
            llm=self.llm,
            verbose=True,
            allow_delegation=False,
            max_iter=3,
        )

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
            1. Identify performance bottlenecks and their root causes
            2. Correlate performance issues with user experience impact
            3. Provide specific optimization strategies with expected improvements
            4. Prioritize optimizations by impact vs effort ratio
            5. Include code examples and configuration changes

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
            1. Assess WCAG 2.1 AA compliance gaps
            2. Identify barriers for users with disabilities
            3. Provide specific ARIA and HTML remediation strategies
            4. Prioritize fixes by user impact and implementation complexity
            5. Include code examples for accessibility improvements

            Focus on inclusive design and assistive technology compatibility.
            """,
            agent=self.agents[2],  # Accessibility agent
            expected_output="Detailed accessibility compliance roadmap",
        )

        # Coordination Task
        coordination_task = Task(
            description="""
            Synthesize the expert analyses from Security, Performance, and Accessibility teams
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
            agent=self.agents[3],  # Coordinator agent
            expected_output="Executive-ready comprehensive analysis and action plan",
            context=[security_task, performance_task, accessibility_task],
        )

        self.tasks = [
            security_task,
            performance_task,
            accessibility_task,
            coordination_task,
        ]
        logger.info(f"✅ Created {len(self.tasks)} analysis tasks")

    def analyze_report(self, report: ComprehensiveAnalysisReport) -> dict[str, Any]:
        """Perform multi-agent analysis of the comprehensive report."""
        try:
            logger.info("🚀 Starting CrewAI multi-agent analysis...")

            # Prepare data for agents
            report_data = self._prepare_report_data(report)

            # Create agents and tasks
            self.create_agents()
            self.create_tasks(report_data)

            # Create and execute crew
            self.crew = Crew(
                agents=self.agents,
                tasks=self.tasks,
                verbose=True,
                process_order_strategy="sequential",  # Execute tasks in order
            )

            # Execute the crew
            logger.info("🔄 Executing agent crew...")
            result = self.crew.kickoff()  # type: ignore

            logger.info("✅ CrewAI analysis completed successfully")

            # Format results
            return self._format_crew_results(result)

        except Exception as e:
            logger.error(f"❌ CrewAI analysis failed: {str(e)}")
            return {
                "success": False,
                "error": str(e),
                "fallback_analysis": "Multi-agent analysis failed, falling back to single LLM analysis",
            }

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
            "security_metrics": {},
            "performance_metrics": {},
            "accessibility_metrics": {},
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
