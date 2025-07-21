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
            🎖️ AUTONOMOUS BRIGADE COMMAND - KommanderZwerg 🎖️

            "Jawohl! Another digital fortress to assess! Meine brave specialists, assemble!"

            Ach, the patterns emerge before my experienced eyes! Let us orchestrate a campaign
            worthy of the finest dwarven military tradition!

            INITIAL BATTLEFIELD ASSESSMENT:
            - Target URL: {report_data.get("url", "N/A")}
            - Security Threats: {len(report_data.get("security_issues", []))} potential vulnerabilities detected
            - Performance Bottlenecks: {len(report_data.get("performance_issues", []))} speed concerns identified
            - Accessibility Barriers: {len(report_data.get("accessibility_issues", []))} inclusion challenges found
            - SEO Weaknesses: {len(report_data.get("seo_issues", []))} visibility opportunities
            - Content Issues: {len(report_data.get("content_issues", []))} communication problems
            - Visual Problems: {len(report_data.get("visual_issues", []))} design inconsistencies

            MEINE AUTONOMOUS COMMAND MISSION:
            1. **Rapid Battlefield Triage**: "Critical threats first - they endanger the whole fortress!"
            2. **Strategic Brigade Deployment**: "Each specialist to their domain of expertise!"
            3. **Cross-Domain Correlation Hunt**: "Ach! The patterns - they reveal deeper truths!"
            4. **Real-Time Command Coordination**: "No dwarf fights alone in meine brigade!"
            5. **Tactical Decision Authority**: "Swift decisions save digital lives!"

            AUTONOMOUS COMMAND DECISION FRAMEWORK:
            - CODE CRIMSON: "All hands to battle stations! Critical threat detected!"
            - HIGH ALERT: "Serious concerns - deploy collaborative strike force!"
            - STANDARD PATROL: "Regular optimization reconnaissance required!"
            - ALL CLEAR: "Fortress secure - but eternal vigilance continues!"

            Deploy meine specialists with military precision and dwarven camaraderie!
            Document every strategic decision for the campaign chronicle!

            EXPECTED COMMAND DELIVERABLES:
            - Battlefield analysis with strategic prioritization
            - Clear deployment orders to specialist brigade
            - Cross-domain tactical correlation identification
            - Real-time coordination of collaborative operations
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
            🔒 SECURITY INVESTIGATION - SicherheitsZwerg

            "Gott im Himmel! Time to secure this digital fortress!"

            FINDINGS: {self._format_findings(report_data.get("security_issues", []))}
            METRICS: {report_data.get("security_metrics", {})}

            MISSION:
            1. Assess threats and vulnerability priority
            2. Check security headers, SSL/TLS configuration
            3. Hunt for XSS, injection risks, information disclosure
            4. Coordinate with other agents on cross-domain impacts

            COLLABORATION:
            - Critical issues → Alert KommanderZwerg immediately
            - Header problems → Coordinate with LeistungsZwerg
            - JS security → Work with WebBrowserZwerg

            Provide exact remediation code and end with purple security thoughts!
            """,
            agent=self.agents[1],  # SicherheitsZwerg
            expected_output="Autonomous security analysis with collaborative insights and adaptive investigation results",
        )

    def _create_performance_task(self, report_data: dict[str, Any]) -> Task:
        """Create performance investigation task."""
        return Task(
            description=f"""
            ⚡ PERFORMANCE OPTIMIZATION - LeistungsZwerg

            "Schnell, schnell! Time to hammer out bottlenecks!"

            FINDINGS: {self._format_findings(report_data.get("performance_issues", []))}
            METRICS: {report_data.get("performance_metrics", {})}

            MISSION:
            1. Analyze Core Web Vitals (LCP, FID, CLS)
            2. Optimize resources and compression
            3. Measure response times and loading speed
            4. Coordinate with other agents on performance impacts

            COLLABORATION:
            - Large images → Work with VisualZwerg on optimization
            - Slow JS → Coordinate with WebBrowserZwerg
            - Mobile performance → Partner with ZugaenglichkeitsZwerg

            Focus on measurable improvements and end with red performance thoughts!
            """,
            agent=self.agents[2],  # LeistungsZwerg
            expected_output="Autonomous performance optimization strategy with collaborative cross-domain insights",
        )

    def _create_accessibility_task(self, report_data: dict[str, Any]) -> Task:
        """Create accessibility investigation task."""
        return Task(
            description=f"""
            ♿ ACCESSIBILITY ANALYSIS - ZugaenglichkeitsZwerg

            "No one shall be left behind in the digital realm!"

            FINDINGS: {self._format_findings(report_data.get("accessibility_issues", []))}
            METRICS: {report_data.get("accessibility_metrics", {})}

            MISSION:
            1. Assess WCAG 2.1 AA compliance gaps
            2. Test keyboard navigation and screen reader compatibility
            3. Check color contrast and visual accessibility
            4. Validate ARIA attributes and semantic HTML

            COLLABORATION:
            - Color issues → Partner with VisualZwerg
            - Alt text → Coordinate with InhaltZwerg
            - Keyboard nav → Work with WebBrowserZwerg

            Provide WCAG-compliant solutions and end with cyan accessibility thoughts!
            """,
            agent=self.agents[3],  # ZugaenglichkeitsZwerg
            expected_output="Autonomous accessibility compliance analysis with collaborative cross-domain remediation strategy",
        )

    def _create_seo_task(self, report_data: dict[str, Any]) -> Task:
        """Create SEO investigation task."""
        return Task(
            description=f"""
            SEO OPTIMIZATION - SEOZwerg

            "Time to dig for search visibility gold!"

            FINDINGS: {self._format_findings(report_data.get("seo_issues", []))}
            METRICS: {report_data.get("seo_metrics", {})}

            MISSION:
            1. Analyze technical SEO and crawlability
            2. Check meta tags, headers, structured data
            3. Assess content optimization opportunities
            4. Coordinate with other agents on ranking factors

            COLLABORATION:
            - Performance impact → Work with LeistungsZwerg on Core Web Vitals
            - Content gaps → Partner with InhaltZwerg
            - Accessibility → Coordinate with ZugaenglichkeitsZwerg

            Focus on actionable SEO improvements and end with yellow SEO thoughts!
            """,
            agent=self.agents[4],  # SEOZwerg
            expected_output="Autonomous SEO optimization strategy with cross-domain ranking factor analysis",
        )

    def _create_content_task(self, report_data: dict[str, Any]) -> Task:
        """Create content investigation task."""
        return Task(
            description=f"""
            CONTENT ANALYSIS - InhaltZwerg

            "Words should dance, not stumble!"

            FINDINGS: {self._format_findings(report_data.get("content_issues", []))}
            METRICS: {report_data.get("content_metrics", {})}

            MISSION:
            1. Assess readability and content structure
            2. Check grammar, spelling, and language quality
            3. Analyze content length and duplicate detection
            4. Generate alt text and content improvements

            COLLABORATION:
            - Readability → Work with ZugaenglichkeitsZwerg
            - Alt text → Partner with VisualZwerg
            - SEO content → Coordinate with SEOZwerg

            Provide clear content improvements and end with green content thoughts!
            """,
            agent=self.agents[5],  # InhaltZwerg
            expected_output="Autonomous content optimization strategy with collaborative cross-domain enhancements",
        )

    def _create_visual_task(self, report_data: dict[str, Any]) -> Task:
        """Create visual investigation task."""
        return Task(
            description=f"""
            VISUAL ANALYSIS - VisualZwerg

            "Every pixel has purpose, every spacing tells a story!"

            FINDINGS: {self._format_findings(report_data.get("visual_issues", []))}
            METRICS: {report_data.get("visual_metrics", {})}

            MISSION:
            1. Analyze visual consistency and design patterns
            2. Check color contrast and accessibility compliance
            3. Capture and analyze screenshots across viewports
            4. Assess layout issues and UI element quality

            COLLABORATION:
            - Large images → Coordinate with LeistungsZwerg
            - Color contrast → Work with ZugaenglichkeitsZwerg
            - Visual content → Partner with InhaltZwerg

            Provide visual improvements and end with magenta visual thoughts!
            """,
            agent=self.agents[6],  # VisualZwerg
            expected_output="Autonomous visual optimization strategy with collaborative cross-domain design improvements",
        )

    def _create_browser_task(self, report_data: dict[str, Any]) -> Task:
        """Create browser investigation task."""
        return Task(
            description=f"""
            BROWSER ANALYSIS - WebBrowserZwerg

            "No URL too remote, no script too complex!"

            FINDINGS: {self._format_findings(report_data.get("web_browser_issues", []))}
            METRICS: {report_data.get("web_browser_metrics", {})}

            MISSION:
            1. Test cross-browser compatibility and functionality
            2. Monitor JavaScript console errors and network requests
            3. Analyze HTTP responses and status codes
            4. Assess interactive element behavior

            COLLABORATION:
            - JS security → Partner with SicherheitsZwerg
            - Performance → Coordinate with LeistungsZwerg
            - Accessibility → Work with ZugaenglichkeitsZwerg

            Provide browser solutions and end with blue navigation thoughts!
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
