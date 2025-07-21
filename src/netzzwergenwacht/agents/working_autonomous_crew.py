"""Working autonomous crew orchestrator without emoji encoding issues."""

import os
from typing import Any

from crewai import Crew, Task
from crewai.agent import BaseAgent
from langchain_openai import ChatOpenAI

from ..dwarfs.base import ComprehensiveAnalysisReport
from ..utils.logging import get_logger
from .accessibility_agent import AccessibilityExpertAgent
from .autonomous_communication import (
    communication_hub,
)
from .content_agent import ContentExpertAgent
from .dokumentalist_zwerg import DokumentalistZwergAgent
from .kommander_zwerg import KommanderZwergAgent
from .performance_agent import PerformanceExpertAgent
from .security_agent import SecurityExpertAgent
from .seo_agent import SEOExpertAgent
from .visual_agent import VisualExpertAgent
from .web_browser_agent import WebBrowserExpertAgent

logger = get_logger("working_autonomous_crew")


class WorkingAutonomousCrew:
    """Working autonomous multi-agent crew without encoding issues."""

    def __init__(self, model: str = "gpt-4o-mini", temperature: float = 0.2):
        """Initialize the working autonomous crew."""
        self.api_key = os.getenv("OPENAI_API_KEY")
        if not self.api_key:
            raise ValueError("OPENAI_API_KEY environment variable not set")

        self.llm = ChatOpenAI(
            model=model,
            temperature=temperature,
            api_key=self.api_key,
        )

        self.agents: list[BaseAgent] = []
        self.tasks: list[Task] = []
        self.crew: Crew | None = None

        # Autonomous agents
        self.kommander = KommanderZwergAgent(llm=self.llm)
        self.dokumentalist = DokumentalistZwergAgent(llm=self.llm)

        logger.info(f"🤖 Working Autonomous CrewAI initialized with model: {model}")
        print("\nAutonomous NetzZwergenWacht Brigade Activating...")

    def create_autonomous_agents(self) -> None:
        """Create autonomous agents with specialized roles."""
        print("Assembling autonomous agent brigade...")

        # Create specialist agents
        security_agent_instance = SecurityExpertAgent(llm=self.llm)
        performance_agent_instance = PerformanceExpertAgent(llm=self.llm)
        accessibility_agent_instance = AccessibilityExpertAgent(llm=self.llm)
        seo_agent_instance = SEOExpertAgent(llm=self.llm)
        content_agent_instance = ContentExpertAgent(llm=self.llm)
        visual_agent_instance = VisualExpertAgent(llm=self.llm)
        web_browser_agent_instance = WebBrowserExpertAgent(llm=self.llm)

        # Create command structure
        kommander_agent = self.kommander.create_agent()
        dokumentalist_agent = self.dokumentalist.create_agent()

        self.agents = [
            kommander_agent,  # 0 - Strategic command
            security_agent_instance.create_agent(),  # 1 - SicherheitsZwerg
            performance_agent_instance.create_agent(),  # 2 - LeistungsZwerg
            accessibility_agent_instance.create_agent(),  # 3 - ZugaenglichkeitsZwerg
            seo_agent_instance.create_agent(),  # 4 - SEOZwerg
            content_agent_instance.create_agent(),  # 5 - InhaltZwerg
            visual_agent_instance.create_agent(),  # 6 - VisualZwerg
            web_browser_agent_instance.create_agent(),  # 7 - WebBrowserZwerg
            dokumentalist_agent,  # 8 - DokumentalistZwerg
        ]

        logger.info(f"✅ Created {len(self.agents)} autonomous agents")
        print(f"✅ {len(self.agents)} autonomous agents ready for deployment")

    def create_autonomous_tasks(self, report_data: dict[str, Any]) -> None:
        """Create adaptive tasks based on autonomous analysis."""
        print("\nKommanderZwerg: Beginning strategic analysis...")

        # Clear previous communication history for this analysis
        communication_hub.message_history.clear()
        communication_hub.active_tasks.clear()

        # KommanderZwerg analyzes initial findings and creates investigation tasks
        self.kommander.analyze_initial_findings(report_data)

        # DokumentalistZwerg starts observing
        self.dokumentalist.observe_agent_conversations()

        # Create initial reconnaissance task
        initial_recon_task = Task(
            description=f"""
            AUTONOMOUS ANALYSIS PHASE 1: Initial Reconnaissance

            As KommanderZwerg, analyze the initial website analysis findings and orchestrate
            real-time autonomous investigation with your specialist brigade.

            INITIAL FINDINGS SUMMARY:
            - URL: {report_data.get("url", "N/A")}
            - Security Issues: {len(report_data.get("security_issues", []))} findings
            - Performance Issues: {len(report_data.get("performance_issues", []))} findings
            - Accessibility Issues: {len(report_data.get("accessibility_issues", []))} findings
            - SEO Issues: {len(report_data.get("seo_issues", []))} findings
            - Content Issues: {len(report_data.get("content_issues", []))} findings
            - Visual Issues: {len(report_data.get("visual_issues", []))} findings

            YOUR AUTONOMOUS MISSION:
            1. **Rapid Triage**: Identify critical issues requiring immediate investigation
            2. **Strategic Delegation**: Assign specialized agents to high-priority areas
            3. **Cross-Domain Analysis**: Identify correlations between different issue types
            4. **Real-Time Coordination**: Orchestrate collaborative investigations
            5. **Decision Making**: Make autonomous decisions about follow-up investigations

            AUTONOMOUS DECISION FRAMEWORK:
            - CRITICAL: Security vulnerabilities, major accessibility violations, severe performance issues
            - HIGH: Cross-domain correlations, compliance risks, user experience blockers
            - MEDIUM: Optimization opportunities, minor compliance gaps
            - LOW: Nice-to-have improvements, cosmetic issues

            Communicate with your brigade using clear, decisive commands. Document your
            strategic decisions and rationale for the final report.

            EXPECTED DELIVERABLES:
            - Strategic analysis of findings prioritization
            - Delegation commands to specialist agents
            - Identification of cross-domain investigation opportunities
            - Real-time collaboration coordination with other agents
            """,
            agent=self.agents[0],  # KommanderZwerg
            expected_output="Strategic analysis with autonomous delegation decisions and real-time coordination",
        )

        # Create specialist investigation tasks
        security_task = self._create_security_task(report_data)
        performance_task = self._create_performance_task(report_data)
        accessibility_task = self._create_accessibility_task(report_data)
        seo_task = self._create_seo_task(report_data)
        content_task = self._create_content_task(report_data)
        visual_task = self._create_visual_task(report_data)
        browser_task = self._create_browser_task(report_data)

        # Create final synthesis task
        synthesis_task = Task(
            description="""
            AUTONOMOUS ANALYSIS FINAL PHASE: Comprehensive Documentation

            As DokumentalistZwerg, synthesize all autonomous agent findings, real-time collaborations,
            and strategic decisions into a comprehensive analysis report.

            AUTONOMOUS INVESTIGATION SYNTHESIS:
            You have observed the entire autonomous multi-agent investigation process including:
            - KommanderZwerg's strategic decisions and delegations
            - Real-time agent collaborations and cross-domain discoveries
            - Autonomous follow-up investigations and adaptations
            - Cross-agent communication patterns and insights

            YOUR SYNTHESIS MISSION:
            1. **Executive Summary**: High-level overview of autonomous investigation results
            2. **Critical Findings**: Priority-ranked issues discovered through agent collaboration
            3. **Cross-Domain Correlations**: Connections identified through multi-agent analysis
            4. **Autonomous Insights**: Unique discoveries made through real-time agent cooperation
            5. **Strategic Roadmap**: Prioritized remediation plan based on collaborative findings
            6. **Collaboration Analysis**: Assessment of multi-agent decision-making effectiveness

            REPORT STRUCTURE:
            - Executive Summary (business-focused, strategic overview)
            - Critical Findings by Priority (immediate actions required)
            - Cross-Domain Analysis (systemic issues and correlations)
            - Autonomous Intelligence Insights (emergent discoveries)
            - Implementation Roadmap (phased remediation strategy)
            - Technical Appendix (detailed findings and agent communications)

            This report should demonstrate the power of autonomous multi-agent collaboration
            in uncovering insights that single-agent analysis would miss.
            """,
            agent=self.agents[8],  # DokumentalistZwerg
            expected_output="Comprehensive autonomous investigation synthesis report",
            context=[
                initial_recon_task,
                security_task,
                performance_task,
                accessibility_task,
                seo_task,
                content_task,
                visual_task,
                browser_task,
            ],
        )

        self.tasks = [
            initial_recon_task,
            security_task,
            performance_task,
            accessibility_task,
            seo_task,
            content_task,
            visual_task,
            browser_task,
            synthesis_task,
        ]

        logger.info(f"✅ Created {len(self.tasks)} autonomous investigation tasks")
        print(f"✅ {len(self.tasks)} autonomous tasks prepared")

    def _create_security_task(self, report_data: dict[str, Any]) -> Task:
        """Create security investigation task."""
        return Task(
            description=f"""
            AUTONOMOUS SECURITY INVESTIGATION - SicherheitsZwerg

            Conduct autonomous security analysis with real-time collaboration and adaptive investigation.

            SECURITY INTELLIGENCE BRIEFING:
            {self._format_findings(report_data.get("security_issues", []))}

            Security Metrics: {report_data.get("security_metrics", {})}

            AUTONOMOUS INVESTIGATION PROTOCOL:
            1. **Threat Assessment**: Analyze security findings for immediate threats
            2. **Vulnerability Prioritization**: Rank vulnerabilities by exploitability and impact
            3. **Cross-Domain Security Impact**: Identify how security issues affect other domains
            4. **Real-Time Collaboration**: Coordinate with WebBrowserZwerg for JavaScript security analysis
            5. **Adaptive Deep-Dive**: Based on findings severity, request additional specialized scans

            COLLABORATIVE INTELLIGENCE:
            - If critical vulnerabilities found -> Alert KommanderZwerg immediately
            - If header issues detected -> Coordinate with PerformanceZwerg for impact analysis
            - If JavaScript risks identified -> Delegate XSS testing to WebBrowserZwerg
            - If SSL/TLS issues -> Assess impact on SEO and user trust with SEOZwerg

            AUTONOMOUS DECISION TRIGGERS:
            - CRITICAL: Immediate escalation to KommanderZwerg for emergency protocols
            - HIGH: Cross-domain collaboration requests for comprehensive assessment
            - MEDIUM: Standard remediation recommendations with priority timelines

            Provide specific, actionable security remediation with exact code examples.
            """,
            agent=self.agents[1],  # SicherheitsZwerg
            expected_output="Autonomous security analysis with collaborative insights and adaptive investigation results",
        )

    def _create_performance_task(self, report_data: dict[str, Any]) -> Task:
        """Create performance investigation task."""
        return Task(
            description=f"""
            AUTONOMOUS PERFORMANCE INVESTIGATION - LeistungsZwerg

            Execute autonomous performance analysis with adaptive optimization strategies and cross-domain collaboration.

            PERFORMANCE INTELLIGENCE BRIEFING:
            {self._format_findings(report_data.get("performance_issues", []))}

            Performance Metrics: {report_data.get("performance_metrics", {})}

            AUTONOMOUS OPTIMIZATION PROTOCOL:
            1. **Performance Triage**: Identify bottlenecks with highest user impact
            2. **Core Web Vitals Analysis**: Assess LCP, FID, CLS for search ranking impact
            3. **Resource Optimization**: Analyze assets for compression and delivery optimization
            4. **Cross-Domain Performance Impact**: Coordinate with other agents on shared optimizations
            5. **Adaptive Investigation**: Scale analysis depth based on performance severity

            COLLABORATIVE OPTIMIZATION:
            - Large images detected -> Collaborate with VisualZwerg on image optimization strategy
            - Slow JavaScript -> Coordinate with WebBrowserZwerg for code analysis
            - Poor mobile performance -> Work with ZugaenglichkeitsZwerg on responsive optimization
            - SEO impact detected -> Alert SEOZwerg to search ranking implications

            AUTONOMOUS DECISION FRAMEWORK:
            - CRITICAL (<= 2s load time): Immediate multi-agent optimization task force
            - HIGH (2-5s): Coordinated optimization with visual and content teams
            - MEDIUM (5-10s): Standard optimization with monitoring recommendations

            Focus on measurable improvements with clear before/after metrics.
            """,
            agent=self.agents[2],  # LeistungsZwerg
            expected_output="Autonomous performance optimization strategy with collaborative cross-domain insights",
        )

    def _create_accessibility_task(self, report_data: dict[str, Any]) -> Task:
        """Create accessibility investigation task."""
        return Task(
            description=f"""
            AUTONOMOUS ACCESSIBILITY INVESTIGATION - ZugaenglichkeitsZwerg

            Conduct autonomous accessibility analysis with adaptive WCAG compliance assessment and collaborative remediation.

            ACCESSIBILITY INTELLIGENCE BRIEFING:
            {self._format_findings(report_data.get("accessibility_issues", []))}

            Accessibility Metrics: {report_data.get("accessibility_metrics", {})}

            AUTONOMOUS COMPLIANCE PROTOCOL:
            1. **WCAG 2.1 AA Triage**: Prioritize violations by user impact and legal risk
            2. **EU Accessibility Act Assessment**: Evaluate compliance gaps for European market
            3. **Cross-Domain Accessibility**: Identify accessibility issues spanning multiple domains
            4. **Collaborative Remediation**: Coordinate fixes with visual, content, and technical teams
            5. **Adaptive Testing**: Scale testing depth based on violation severity and user impact

            COLLABORATIVE ACCESSIBILITY:
            - Color contrast issues -> Partner with VisualZwerg for design-compliant solutions
            - Alt text missing -> Work with InhaltZwerg for meaningful image descriptions
            - Keyboard navigation problems -> Coordinate with WebBrowserZwerg for interaction fixes
            - Form accessibility -> Collaborate across teams for comprehensive form optimization

            AUTONOMOUS PRIORITY FRAMEWORK:
            - CRITICAL: Screen reader blocking issues, keyboard trap violations
            - HIGH: Color contrast failures, missing form labels, heading structure problems
            - MEDIUM: Alt text improvements, ARIA enhancements, focus management
            - LOW: Nice-to-have accessibility improvements

            Provide specific WCAG 2.1 AA compliant solutions with exact code implementations.
            """,
            agent=self.agents[3],  # ZugaenglichkeitsZwerg
            expected_output="Autonomous accessibility compliance analysis with collaborative cross-domain remediation strategy",
        )

    def _create_seo_task(self, report_data: dict[str, Any]) -> Task:
        """Create SEO investigation task."""
        return Task(
            description=f"""
            AUTONOMOUS SEO INVESTIGATION - SEOZwerg

            Execute autonomous SEO analysis with adaptive optimization strategies and cross-domain search ranking impact assessment.

            SEO INTELLIGENCE BRIEFING:
            {self._format_findings(report_data.get("seo_issues", []))}

            SEO Metrics: {report_data.get("seo_metrics", {})}

            AUTONOMOUS SEO OPTIMIZATION PROTOCOL:
            1. **Search Visibility Triage**: Identify factors with highest ranking impact
            2. **Technical SEO Assessment**: Analyze crawlability, indexability, and performance signals
            3. **Content Optimization**: Evaluate on-page factors and content quality signals
            4. **Cross-Domain SEO Impact**: Coordinate with other agents on ranking factors
            5. **Adaptive Analysis**: Scale SEO investigation based on competitive landscape

            COLLABORATIVE SEO STRATEGY:
            - Performance issues detected -> Coordinate with LeistungsZwerg on Core Web Vitals impact
            - Content quality problems -> Partner with InhaltZwerg for content optimization strategy
            - Accessibility violations -> Work with ZugaenglichkeitsZwerg (accessibility is ranking factor)
            - Security issues -> Alert that HTTPS and security headers affect trust signals

            AUTONOMOUS SEO DECISION FRAMEWORK:
            - CRITICAL: Missing title tags, severe technical SEO issues, crawl errors
            - HIGH: Meta description gaps, heading structure problems, performance impact
            - MEDIUM: Structured data opportunities, internal linking optimization
            - LOW: Minor on-page optimizations, enhancement opportunities

            Focus on actionable SEO improvements with measurable ranking potential.
            """,
            agent=self.agents[4],  # SEOZwerg
            expected_output="Autonomous SEO optimization strategy with cross-domain ranking factor analysis",
        )

    def _create_content_task(self, report_data: dict[str, Any]) -> Task:
        """Create content investigation task."""
        return Task(
            description=f"""
            AUTONOMOUS CONTENT INVESTIGATION - InhaltZwerg

            Conduct autonomous content quality analysis with adaptive optimization and collaborative enhancement strategies.

            CONTENT INTELLIGENCE BRIEFING:
            {self._format_findings(report_data.get("content_issues", []))}

            Content Metrics: {report_data.get("content_metrics", {})}

            AUTONOMOUS CONTENT OPTIMIZATION PROTOCOL:
            1. **Content Quality Triage**: Assess readability, structure, and user engagement factors
            2. **Accessibility Content Review**: Ensure content supports assistive technologies
            3. **SEO Content Analysis**: Evaluate content for search optimization opportunities
            4. **Cross-Domain Content Impact**: Identify content issues affecting other domains
            5. **Adaptive Enhancement**: Scale content improvements based on user impact

            COLLABORATIVE CONTENT STRATEGY:
            - Readability issues -> Coordinate with ZugaenglichkeitsZwerg for cognitive accessibility
            - Image alt text needed -> Partner with VisualZwerg for accurate image descriptions
            - SEO content gaps -> Work with SEOZwerg for keyword and structure optimization
            - Performance impact -> Alert LeistungsZwerg if content affects loading speed

            AUTONOMOUS CONTENT DECISION FRAMEWORK:
            - CRITICAL: Content blocking accessibility, severe readability issues
            - HIGH: Missing alt text, poor content structure, readability below target
            - MEDIUM: Content optimization opportunities, duplicate content issues
            - LOW: Content enhancement and engagement improvements

            Provide specific content improvements with clear implementation guidance.
            """,
            agent=self.agents[5],  # InhaltZwerg
            expected_output="Autonomous content optimization strategy with collaborative cross-domain enhancements",
        )

    def _create_visual_task(self, report_data: dict[str, Any]) -> Task:
        """Create visual investigation task."""
        return Task(
            description=f"""
            AUTONOMOUS VISUAL INVESTIGATION - VisualZwerg

            Execute autonomous visual analysis with adaptive design optimization and collaborative user experience enhancement.

            VISUAL INTELLIGENCE BRIEFING:
            {self._format_findings(report_data.get("visual_issues", []))}

            Visual Metrics: {report_data.get("visual_metrics", {})}

            AUTONOMOUS VISUAL OPTIMIZATION PROTOCOL:
            1. **Visual Consistency Analysis**: Assess design patterns, spacing, and brand coherence
            2. **Performance-Visual Balance**: Optimize visual elements without compromising loading speed
            3. **Accessibility Visual Compliance**: Ensure visual design supports all users
            4. **Cross-Domain Visual Impact**: Coordinate visual improvements with technical requirements
            5. **Adaptive Design Enhancement**: Scale visual improvements based on user experience impact

            COLLABORATIVE VISUAL STRATEGY:
            - Large images affecting performance -> Coordinate optimization with LeistungsZwerg
            - Color contrast violations -> Work with ZugaenglichkeitsZwerg for compliant alternatives
            - Visual content without alt text -> Partner with InhaltZwerg for descriptions
            - Visual consistency affecting brand -> Consider SEO trust signal impact with SEOZwerg

            AUTONOMOUS VISUAL DECISION FRAMEWORK:
            - CRITICAL: Accessibility-blocking visual issues, broken layouts affecting usability
            - HIGH: Performance-impacting visual elements, contrast violations, inconsistent branding
            - MEDIUM: Visual optimization opportunities, design enhancement possibilities
            - LOW: Nice-to-have visual improvements, aesthetic refinements

            Provide specific visual design improvements with implementation details and performance considerations.
            """,
            agent=self.agents[6],  # VisualZwerg
            expected_output="Autonomous visual optimization strategy with collaborative cross-domain design improvements",
        )

    def _create_browser_task(self, report_data: dict[str, Any]) -> Task:
        """Create browser investigation task."""
        return Task(
            description=f"""
            AUTONOMOUS BROWSER INVESTIGATION - WebBrowserZwerg

            Conduct autonomous browser-based analysis with adaptive cross-browser compatibility and collaborative technical assessment.

            BROWSER INTELLIGENCE BRIEFING:
            {self._format_findings(report_data.get("web_browser_issues", []))}

            Browser Metrics: {report_data.get("web_browser_metrics", {})}

            AUTONOMOUS BROWSER ANALYSIS PROTOCOL:
            1. **Cross-Browser Compatibility**: Test functionality across major browsers and devices
            2. **JavaScript Security Analysis**: Identify client-side security vulnerabilities
            3. **Interactive Element Assessment**: Verify accessibility and performance of dynamic content
            4. **Collaborative Technical Investigation**: Support other agents with browser-based insights
            5. **Adaptive Testing**: Scale browser testing based on issue complexity and user impact

            COLLABORATIVE BROWSER STRATEGY:
            - JavaScript security risks -> Partner with SicherheitsZwerg for comprehensive security assessment
            - Performance bottlenecks in browser -> Coordinate with LeistungsZwerg for optimization
            - Interactive accessibility issues -> Work with ZugaenglichkeitsZwerg for inclusive solutions
            - Browser-specific visual problems -> Collaborate with VisualZwerg for consistent experience

            AUTONOMOUS BROWSER DECISION FRAMEWORK:
            - CRITICAL: Security vulnerabilities, accessibility-blocking JavaScript, broken core functionality
            - HIGH: Cross-browser compatibility issues, performance-impacting scripts, usability problems
            - MEDIUM: Browser optimization opportunities, minor compatibility improvements
            - LOW: Nice-to-have browser enhancements, future-proofing considerations

            Provide specific browser compatibility solutions with cross-platform testing recommendations.
            """,
            agent=self.agents[7],  # WebBrowserZwerg
            expected_output="Autonomous browser compatibility analysis with collaborative technical insights",
        )

    def _format_findings(self, findings: list[dict[str, Any]]) -> str:
        """Format findings data for agent consumption."""
        if not findings:
            return "No significant issues detected in initial analysis."

        formatted = []
        for i, finding in enumerate(findings[:5], 1):  # Limit to top 5 findings
            severity = finding.get("severity", "unknown").upper()
            issue_type = finding.get("type", "unknown_issue")
            description = finding.get("description", "No description provided")

            formatted.append(f"{i}. [{severity}] {issue_type}: {description}")

        if len(findings) > 5:
            formatted.append(f"... and {len(findings) - 5} additional findings")

        return "\n".join(formatted)

    def analyze(self, report: ComprehensiveAnalysisReport) -> dict[str, Any]:
        """
        Execute autonomous multi-agent analysis with real-time collaboration.

        Args:
            report: The comprehensive analysis report from initial Dwarf analysis.

        Returns:
            A dictionary with the autonomous analysis results.
        """
        try:
            print("\nLaunching Autonomous Multi-Agent Analysis...")
            print("=" * 60)

            self.create_autonomous_agents()
            report_data = self._prepare_report_data(report)
            self.create_autonomous_tasks(report_data)

            # Create autonomous crew
            self.crew = Crew(
                agents=self.agents,
                tasks=self.tasks,
                verbose=True,
                memory=True,  # Enable memory for cross-task context
            )

            print("\nKommanderZwerg: Initiating autonomous brigade operations...")
            print("Real-time agent communications will be displayed below:")
            print("-" * 60)

            # Execute autonomous analysis
            crew_result = self.crew.kickoff()

            print("\n" + "=" * 60)
            print("✅ Autonomous multi-agent analysis completed!")

            return self._format_autonomous_results(crew_result)

        except Exception as e:
            logger.error(f"❌ Autonomous analysis error: {e}")
            return {
                "success": False,
                "error": str(e),
                "analysis_type": "autonomous_multi_agent_collaboration",
            }

    def _prepare_report_data(
        self, report: ComprehensiveAnalysisReport
    ) -> dict[str, Any]:
        """Prepare report data for autonomous agent consumption."""
        data = {
            "url": report.url,
            "total_issues": report.total_issues,
            "critical_issues": report.critical_issues,
            "high_issues": report.high_issues,
            "analysis_duration": report.analysis_duration_seconds,
            "security_issues": [],
            "performance_issues": [],
            "accessibility_issues": [],
            "seo_issues": [],
            "content_issues": [],
            "visual_issues": [],
            "web_browser_issues": [],
            "security_metrics": {},
            "performance_metrics": {},
            "accessibility_metrics": {},
            "seo_metrics": {},
            "content_metrics": {},
            "visual_metrics": {},
            "web_browser_metrics": {},
        }

        # Extract detailed issues by category for autonomous analysis
        for result in report.dwarf_results:
            if not result.success:
                continue

            dwarf_type = result.dwarf_name.lower()

            # Convert detailed issues to agent-friendly format
            issues_data = [
                {
                    "type": issue.issue_type,
                    "severity": issue.severity.value,
                    "description": issue.description,
                    "impact": issue.impact,
                    "location": issue.location,
                    "fix_suggestions": issue.fix_suggestions,
                    "priority_score": issue.priority_score,
                    "technical_details": issue.technical_details,
                }
                for issue in result.detailed_issues
            ]

            if "security" in dwarf_type or "sicherheits" in dwarf_type:
                data["security_issues"] = issues_data
                if hasattr(result, "security_metrics") and result.security_metrics:
                    data["security_metrics"] = result.security_metrics.__dict__

            elif "performance" in dwarf_type or "leistungs" in dwarf_type:
                data["performance_issues"] = issues_data
                if (
                    hasattr(result, "performance_metrics")
                    and result.performance_metrics
                ):
                    data["performance_metrics"] = result.performance_metrics.__dict__

            elif "accessibility" in dwarf_type or "zugaenglichkeits" in dwarf_type:
                data["accessibility_issues"] = issues_data
                if (
                    hasattr(result, "accessibility_metrics")
                    and result.accessibility_metrics
                ):
                    data["accessibility_metrics"] = (
                        result.accessibility_metrics.__dict__
                    )

            elif "seo" in dwarf_type:
                data["seo_issues"] = issues_data
                if hasattr(result, "seo_metrics") and result.seo_metrics:
                    data["seo_metrics"] = result.seo_metrics.__dict__

            elif "inhalt" in dwarf_type or "content" in dwarf_type:
                data["content_issues"] = issues_data
                if hasattr(result, "content_metrics") and result.content_metrics:
                    data["content_metrics"] = result.content_metrics.__dict__

            elif "visual" in dwarf_type:
                data["visual_issues"] = issues_data
                if hasattr(result, "visual_metrics") and result.visual_metrics:
                    data["visual_metrics"] = result.visual_metrics.__dict__

            elif "web_browser" in dwarf_type:
                data["web_browser_issues"] = issues_data
                if (
                    hasattr(result, "web_browser_metrics")
                    and result.web_browser_metrics
                ):
                    data["web_browser_metrics"] = result.web_browser_metrics.__dict__

        return data

    def _format_autonomous_results(self, crew_result: Any) -> dict[str, Any]:
        """Format autonomous crew execution results."""
        # Get collaboration analysis from DokumentalistZwerg
        collaboration_analysis = self.dokumentalist.analyze_collaboration_patterns()

        return {
            "success": True,
            "model": "Working Autonomous CrewAI Multi-Agent Brigade",
            "analysis": str(crew_result),
            "agent_count": len(self.agents),
            "task_count": len(self.tasks),
            "analysis_type": "autonomous_multi_agent_collaboration",
            "agents_used": [agent.role for agent in self.agents],
            "autonomous_features": {
                "real_time_collaboration": True,
                "adaptive_investigation": True,
                "cross_domain_correlation": True,
                "autonomous_decision_making": True,
                "strategic_delegation": True,
            },
            "collaboration_metrics": collaboration_analysis,
            "communication_history": [
                {
                    "timestamp": msg.timestamp.isoformat(),
                    "sender": msg.sender,
                    "recipient": msg.recipient,
                    "type": msg.message_type.value,
                    "content": msg.content,
                    "priority": msg.priority.value,
                }
                for msg in communication_hub.message_history
            ],
        }
