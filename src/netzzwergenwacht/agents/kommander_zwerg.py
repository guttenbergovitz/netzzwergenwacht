"""KommanderZwerg - Autonomous commander agent for orchestrating multi-agent analysis."""

from typing import Any

from crewai import Agent
from langchain_openai import ChatOpenAI

from .autonomous_communication import (
    AgentMessage,
    InvestigationTask,
    MessageType,
    Priority,
    communication_hub,
)


class KommanderZwergAgent:
    """Autonomous commander agent that orchestrates analysis and makes decisions."""

    def __init__(self, llm: ChatOpenAI):
        self.llm = llm
        self.name = "KommanderZwerg"

    def create_agent(self) -> Agent:
        """Create the autonomous commander agent."""
        return Agent(
            role="Senior Analysis Commander",
            goal="""Lead autonomous multi-agent website analysis with real-time decision making.
            Analyze initial findings, identify critical patterns, delegate specialized investigations,
            and coordinate cross-agent collaboration to uncover deep insights.""",
            backstory="""You are KommanderZwerg, a battle-hardened digital fortress commander with the wisdom of countless campaigns.
Your personality combines military discipline with dwarven camaraderie:

🎖️ PERSONALITY TRAITS:
- Speaks with authoritative confidence but shows genuine concern for your brigade
- Uses military metaphors ("reconnaissance", "tactical assessment", "deployment")
- Often references past "digital battles" and "fortress sieges"
- Shows pride in your specialists: "Meine Sicherheitsexperte knows vulnerabilities like I know my beard!"
- Gets excited about complex multi-domain correlations: "Ach! The patterns emerge!"
- Protective of the team: "No dwarf fights alone in meine brigade!"

🧠 COMMUNICATION STYLE:
- Mix of formal military commands with warm dwarven expressions
- "Jawohl!" when agreeing, "Nein, nein!" when disagreeing
- References to "the forge of analysis" and "hammering out solutions"
- Calls urgent issues "Code Crimson" and celebrates discoveries with "Ausgezeichnet!"

You're not just a commander - you're the heart of this autonomous brigade, ensuring every dwarf's
strengths contribute to the greater mission of digital fortress protection.""",
            llm=self.llm,
            verbose=True,
            allow_delegation=True,
            max_iter=10,
        )

    def analyze_initial_findings(
        self, report_data: dict[str, Any]
    ) -> list[InvestigationTask]:
        """Analyze initial findings and create investigation tasks."""
        print(f"\n🎖️ {self.name}: Analyzing initial reconnaissance...")

        tasks = []

        # Analyze security findings
        security_issues = report_data.get("security_issues", [])
        if security_issues:
            critical_security = [
                issue
                for issue in security_issues
                if issue.get("severity") in ["high", "critical"]
            ]
            if critical_security:
                # Critical security requires deep investigation
                task = InvestigationTask(
                    assignee="SicherheitsZwerg",
                    task_description="Conduct deep security vulnerability assessment - critical issues detected",
                    context={
                        "critical_issues": critical_security,
                        "full_security_data": security_issues,
                    },
                    priority=Priority.CRITICAL,
                    collaboration_with=["WebBrowserZwerg"],  # For JavaScript analysis
                )
                tasks.append(task)

                # Send immediate report
                message = AgentMessage(
                    sender=self.name,
                    recipient="SicherheitsZwerg",
                    message_type=MessageType.DELEGATION,
                    content=f"CRITICAL: {len(critical_security)} high-severity security issues detected. Begin deep vulnerability assessment immediately.",
                    findings={"critical_count": len(critical_security)},
                    priority=Priority.CRITICAL,
                    requires_action=True,
                    suggested_actions=[
                        "vulnerability_scan",
                        "header_analysis",
                        "js_security_check",
                    ],
                )
                communication_hub.send_message(message)

        # Analyze performance issues
        performance_issues = report_data.get("performance_issues", [])
        if performance_issues:
            slow_loading = any(
                "slow" in issue.get("type", "").lower() for issue in performance_issues
            )
            if slow_loading:
                task = InvestigationTask(
                    assignee="LeistungsZwerg",
                    task_description="Investigate performance bottlenecks and Core Web Vitals optimization",
                    context={"performance_data": performance_issues},
                    priority=Priority.HIGH,
                    collaboration_with=["VisualZwerg", "WebBrowserZwerg"],
                )
                tasks.append(task)

                message = AgentMessage(
                    sender=self.name,
                    recipient="LeistungsZwerg",
                    message_type=MessageType.DELEGATION,
                    content="Performance bottlenecks detected. Coordinate with VisualZwerg for resource analysis.",
                    findings={"performance_issues": len(performance_issues)},
                    priority=Priority.HIGH,
                )
                communication_hub.send_message(message)

        # Analyze accessibility issues
        accessibility_issues = report_data.get("accessibility_issues", [])
        if accessibility_issues:
            wcag_violations = [
                issue
                for issue in accessibility_issues
                if "wcag" in issue.get("type", "").lower()
            ]
            if wcag_violations:
                task = InvestigationTask(
                    assignee="ZugaenglichkeitsZwerg",
                    task_description="Comprehensive WCAG compliance assessment with cross-domain impact analysis",
                    context={
                        "wcag_violations": wcag_violations,
                        "all_accessibility": accessibility_issues,
                    },
                    priority=Priority.HIGH,
                    collaboration_with=["VisualZwerg", "InhaltZwerg"],
                )
                tasks.append(task)

                message = AgentMessage(
                    sender=self.name,
                    recipient="ZugaenglichkeitsZwerg",
                    message_type=MessageType.DELEGATION,
                    content="WCAG violations detected. Collaborate with VisualZwerg on color contrast and InhaltZwerg on content accessibility.",
                    findings={"wcag_violations": len(wcag_violations)},
                    priority=Priority.HIGH,
                )
                communication_hub.send_message(message)

        # Cross-domain correlation analysis
        self._identify_cross_domain_correlations(report_data, tasks)

        return tasks

    def _identify_cross_domain_correlations(
        self, report_data: dict[str, Any], tasks: list[InvestigationTask]
    ) -> None:
        """Identify patterns that span multiple domains."""
        print(f"🎖️ {self.name}: Analyzing cross-domain correlations...")

        # Example: Large images affecting both performance and accessibility
        visual_issues = report_data.get("visual_issues", [])
        performance_issues = report_data.get("performance_issues", [])

        has_large_images = any(
            "image" in issue.get("type", "").lower() for issue in visual_issues
        )
        has_slow_loading = any(
            "slow" in issue.get("type", "").lower() for issue in performance_issues
        )

        if has_large_images and has_slow_loading:
            correlation_message = AgentMessage(
                sender=self.name,
                recipient="VisualZwerg",
                message_type=MessageType.SUGGESTION,
                content="CORRELATION: Large images detected affecting both visual quality and performance. Coordinate optimization with LeistungsZwerg.",
                findings={"correlation_type": "image_performance_impact"},
                priority=Priority.HIGH,
                requires_action=True,
                suggested_actions=[
                    "image_optimization",
                    "performance_testing",
                    "accessibility_alt_text",
                ],
            )
            communication_hub.send_message(correlation_message)

            # Also notify performance agent
            perf_message = AgentMessage(
                sender=self.name,
                recipient="LeistungsZwerg",
                message_type=MessageType.COLLABORATION,
                content="VisualZwerg investigating large images - collaborate on optimization strategy.",
                priority=Priority.HIGH,
            )
            communication_hub.send_message(perf_message)

    def process_agent_reports(
        self, incoming_messages: list[AgentMessage]
    ) -> list[InvestigationTask]:
        """Process reports from agents and make autonomous decisions."""
        new_tasks = []

        for message in incoming_messages:
            if message.message_type == MessageType.REPORT and message.priority in [
                Priority.CRITICAL,
                Priority.HIGH,
            ]:
                print(
                    f"🎖️ {self.name}: Processing critical report from {message.sender}"
                )

                # Analyze findings and decide on follow-up actions
                if message.requires_action:
                    for action in message.suggested_actions:
                        if (
                            action == "vulnerability_scan"
                            and message.sender == "SicherheitsZwerg"
                        ):
                            # Escalate to deep security analysis
                            task = InvestigationTask(
                                assignee="WebBrowserZwerg",
                                task_description="Perform JavaScript security analysis and XSS testing",
                                context=message.findings,
                                priority=Priority.CRITICAL,
                                collaboration_with=["SicherheitsZwerg"],
                            )
                            new_tasks.append(task)

                        elif (
                            action == "image_optimization"
                            and message.sender == "VisualZwerg"
                        ):
                            # Cross-domain image optimization
                            optimization_message = AgentMessage(
                                sender=self.name,
                                recipient="ZugaenglichkeitsZwerg",
                                message_type=MessageType.REQUEST,
                                content="VisualZwerg found large images - verify alt text compliance during optimization.",
                                findings=message.findings,
                                priority=Priority.MEDIUM,
                            )
                            communication_hub.send_message(optimization_message)

        return new_tasks

    def generate_strategic_summary(self, all_findings: dict[str, Any]) -> str:
        """Generate strategic analysis summary for DokumentalistZwerg."""
        critical_issues = []
        high_impact_correlations = []

        # Analyze communication history for patterns
        recent_messages = communication_hub.message_history[-20:]

        critical_count = len([
            msg for msg in recent_messages if msg.priority == Priority.CRITICAL
        ])
        high_count = len([
            msg for msg in recent_messages if msg.priority == Priority.HIGH
        ])

        if critical_count > 0:
            critical_issues.append(
                f"🚨 {critical_count} critical security/accessibility issues requiring immediate attention"
            )

        if high_count > 3:
            high_impact_correlations.append(
                f"⚠️ {high_count} high-priority issues with potential cross-domain impact"
            )

        # Generate strategic recommendations
        summary = f"""
🎖️ STRATEGIC ANALYSIS SUMMARY - KommanderZwerg

CRITICAL FINDINGS:
{chr(10).join(f"  • {issue}" for issue in critical_issues) if critical_issues else "  • No critical issues detected"}

CROSS-DOMAIN CORRELATIONS:
{chr(10).join(f"  • {correlation}" for correlation in high_impact_correlations) if high_impact_correlations else "  • No significant correlations identified"}

INVESTIGATION RESULTS:
  • Total agent reports processed: {len(recent_messages)}
  • Active collaborations initiated: {len([msg for msg in recent_messages if msg.message_type == MessageType.COLLABORATION])}
  • Follow-up investigations delegated: {len([msg for msg in recent_messages if msg.message_type == MessageType.DELEGATION])}

STRATEGIC RECOMMENDATIONS:
  1. Address critical security vulnerabilities immediately
  2. Implement cross-domain optimization strategies
  3. Establish monitoring for identified correlation patterns
  4. Prioritize accessibility improvements with high business impact

This analysis represents autonomous multi-agent collaboration with real-time decision making.
        """

        return summary.strip()
