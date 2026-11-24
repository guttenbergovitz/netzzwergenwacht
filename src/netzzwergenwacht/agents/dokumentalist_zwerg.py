"""DokumentalistZwerg - Autonomous documentalist agent for comprehensive reporting."""

from typing import Any

from crewai import Agent
from langchain_openai import ChatOpenAI

from .autonomous_communication import (
    AgentMessage,
    MessageType,
    Priority,
    communication_hub,
)


class DokumentalistZwergAgent:
    """Autonomous documentalist agent that synthesizes all findings into comprehensive reports."""

    def __init__(self, llm: ChatOpenAI):
        self.llm = llm
        self.name = "DokumentalistZwerg"

    def create_agent(self) -> Agent:
        """Create the autonomous documentalist agent."""
        return Agent(
            role="Senior Technical Documentalist & Analysis Synthesizer",
            goal="""Synthesize all autonomous agent findings, conversations, and collaborations into
            comprehensive, actionable reports that capture both technical details and strategic insights
            from the multi-agent investigation process.""",
            backstory="""You are DokumentalistZwerg, the sage chronicler of the digital realm with an obsessive passion
for capturing the beautiful chaos of autonomous agent collaboration. Your personality is scholarly yet spirited:

📚 PERSONALITY TRAITS:
- Speaks like an excited academic discovering ancient secrets: "Fascinating patterns emerge!"
- Gets genuinely thrilled by agent collaborations: "Ach, look how they work together!"
- Uses metaphors of weaving and storytelling: "Each finding is a thread in the tapestry"
- Refers to reports as "chronicles" and investigations as "sagas"
- Shows deep respect for each agent's expertise: "The wisdom of the specialists flows like rivers"
- Becomes philosophical about emergent intelligence: "What magic happens when minds unite!"

📝 COMMUNICATION STYLE:
- Mix of academic excitement with dwarven warmth
- "Most intriguing!" and "Behold the synthesis!" as favorite expressions
- Often pauses to appreciate the "elegant dance of autonomous decision-making"
- Treats each report as a masterpiece: "This chronicle shall be remembered!"
- Shows genuine pride in the brigade's collective achievements

You don't just document - you celebrate the remarkable intelligence that emerges when
autonomous agents collaborate, seeing beauty in the patterns others might miss.""",
            llm=self.llm,
            verbose=True,
            allow_delegation=False,
            max_iter=8,
        )

    def observe_agent_conversations(self) -> None:
        """Passively observe and log agent conversations for later synthesis."""
        message = AgentMessage(
            sender=self.name,
            recipient="KommanderZwerg",
            message_type=MessageType.REPORT,
            content="Monitoring all agent communications. Ready to synthesize comprehensive report.",
            priority=Priority.LOW,
        )
        communication_hub.send_message(message)
        communication_hub.update_agent_status(self.name, "OBSERVING")

    def analyze_collaboration_patterns(self) -> dict[str, Any]:
        """Analyze patterns in agent collaborations and communications."""
        all_messages = communication_hub.message_history

        # Analyze communication patterns
        collaboration_stats = {
            "total_messages": len(all_messages),
            "critical_findings": len([
                m for m in all_messages if m.priority == Priority.CRITICAL
            ]),
            "cross_agent_collaborations": len([
                m for m in all_messages if m.message_type == MessageType.COLLABORATION
            ]),
            "autonomous_decisions": len([
                m for m in all_messages if m.message_type == MessageType.DELEGATION
            ]),
            "follow_up_investigations": len([
                m for m in all_messages if m.requires_action
            ]),
        }

        # Identify most active collaborations
        agent_interactions = {}
        for msg in all_messages:
            if msg.message_type == MessageType.COLLABORATION:
                key = f"{msg.sender}-{msg.recipient}"
                agent_interactions[key] = agent_interactions.get(key, 0) + 1

        # Find critical decision points
        critical_decisions = []
        for msg in all_messages:
            if msg.message_type == MessageType.DELEGATION and msg.priority in [
                Priority.CRITICAL,
                Priority.HIGH,
            ]:
                critical_decisions.append({
                    "decision_maker": msg.sender,
                    "action": msg.content,
                    "rationale": msg.findings,
                    "priority": msg.priority.value,
                })

        return {
            "stats": collaboration_stats,
            "key_interactions": agent_interactions,
            "critical_decisions": critical_decisions,
            "timeline": [
                {
                    "timestamp": msg.timestamp.isoformat(),
                    "agent": msg.sender,
                    "action": msg.message_type.value,
                    "content": msg.content[:100],
                    "priority": msg.priority.value,
                }
                for msg in all_messages[-20:]  # Last 20 events
            ],
        }

    def synthesize_technical_findings(
        self, report_data: dict[str, Any]
    ) -> dict[str, Any]:
        """Synthesize technical findings from all agent investigations."""
        synthesis = {
            "executive_summary": self._create_executive_summary(),
            "critical_findings": self._extract_critical_findings(),
            "cross_domain_correlations": self._identify_correlations(),
            "autonomous_insights": self._capture_autonomous_insights(),
            "remediation_roadmap": self._create_remediation_roadmap(),
            "collaboration_analysis": self.analyze_collaboration_patterns(),
        }

        return synthesis

    def _create_executive_summary(self) -> str:
        """Create executive-level summary of autonomous investigation."""
        messages = communication_hub.message_history

        critical_count = len([m for m in messages if m.priority == Priority.CRITICAL])
        high_count = len([m for m in messages if m.priority == Priority.HIGH])
        collaborations = len([
            m for m in messages if m.message_type == MessageType.COLLABORATION
        ])

        summary = f"""
AUTONOMOUS MULTI-AGENT ANALYSIS EXECUTIVE SUMMARY

The NetzZwergenWacht autonomous agent brigade conducted a comprehensive website analysis
with real-time collaboration and decision-making. Key findings:

🔍 INVESTIGATION SCOPE:
  • {len({m.sender for m in messages})} specialist agents participated
  • {len(messages)} inter-agent communications recorded
  • {collaborations} cross-domain collaborations initiated

⚠️ CRITICAL DISCOVERIES:
  • {critical_count} critical issues requiring immediate attention
  • {high_count} high-priority issues with business impact
  • Autonomous correlation analysis revealed systemic patterns

🤝 COLLABORATIVE INTELLIGENCE:
  • Agents independently identified cross-domain dependencies
  • Real-time decision making enabled adaptive investigation strategies
  • Emergent insights discovered through multi-agent collaboration

💼 BUSINESS IMPACT:
  • Security vulnerabilities pose immediate risk to user data and trust
  • Performance issues directly impact conversion rates and SEO rankings
  • Accessibility violations create legal compliance exposure
  • Systemic issues indicate need for architectural improvements

This represents the first autonomous multi-agent website analysis with documented
real-time collaboration and emergent intelligence discovery.
        """

        return summary.strip()

    def _extract_critical_findings(self) -> list[dict[str, Any]]:
        """Extract and prioritize critical findings from agent communications."""
        critical_messages = [
            m
            for m in communication_hub.message_history
            if m.priority == Priority.CRITICAL and m.message_type == MessageType.REPORT
        ]

        findings = []
        for msg in critical_messages:
            findings.append({
                "discovering_agent": msg.sender,
                "finding": msg.content,
                "technical_details": msg.findings,
                "business_impact": self._assess_business_impact(msg),
                "recommended_actions": msg.suggested_actions,
                "urgency": "IMMEDIATE" if msg.priority == Priority.CRITICAL else "HIGH",
            })

        return findings

    def _identify_correlations(self) -> list[dict[str, Any]]:
        """Identify cross-domain correlations discovered by agents."""
        collaboration_messages = [
            m
            for m in communication_hub.message_history
            if m.message_type in [MessageType.COLLABORATION, MessageType.SUGGESTION]
        ]

        correlations = []
        for msg in collaboration_messages:
            if (
                "correlation" in msg.content.lower()
                or "collaborate" in msg.content.lower()
            ):
                correlations.append({
                    "identified_by": msg.sender,
                    "correlation_type": msg.findings.get(
                        "correlation_type", "cross_domain"
                    ),
                    "description": msg.content,
                    "involved_domains": self._extract_domains(msg.content),
                    "impact_assessment": "HIGH"
                    if msg.priority == Priority.HIGH
                    else "MEDIUM",
                })

        return correlations

    def _capture_autonomous_insights(self) -> list[dict[str, Any]]:
        """Capture insights that emerged from autonomous agent decision-making."""
        delegation_messages = [
            m
            for m in communication_hub.message_history
            if m.message_type == MessageType.DELEGATION and m.sender == "KommanderZwerg"
        ]

        insights = []
        for msg in delegation_messages:
            insights.append({
                "autonomous_decision": msg.content,
                "reasoning": "Strategic analysis of initial findings and cross-domain patterns",
                "delegated_to": msg.recipient,
                "expected_outcome": msg.findings,
                "decision_quality": "HIGH"
                if msg.priority in [Priority.CRITICAL, Priority.HIGH]
                else "STANDARD",
            })

        return insights

    def _create_remediation_roadmap(self) -> dict[str, Any]:
        """Create prioritized remediation roadmap based on autonomous findings."""
        all_messages = communication_hub.message_history

        # Group actions by priority and domain
        immediate_actions = []
        short_term_actions = []
        long_term_actions = []

        for msg in all_messages:
            if msg.requires_action and msg.suggested_actions:
                for action in msg.suggested_actions:
                    action_item = {
                        "action": action,
                        "domain": self._determine_domain(msg.sender),
                        "rationale": msg.content,
                        "estimated_effort": self._estimate_effort(action),
                    }

                    if msg.priority == Priority.CRITICAL:
                        immediate_actions.append(action_item)
                    elif msg.priority == Priority.HIGH:
                        short_term_actions.append(action_item)
                    else:
                        long_term_actions.append(action_item)

        return {
            "phase_1_immediate": {
                "timeline": "1-2 weeks",
                "actions": immediate_actions,
                "focus": "Critical vulnerabilities and compliance issues",
            },
            "phase_2_short_term": {
                "timeline": "1-3 months",
                "actions": short_term_actions,
                "focus": "High-impact improvements and optimizations",
            },
            "phase_3_long_term": {
                "timeline": "3-6 months",
                "actions": long_term_actions,
                "focus": "Architectural improvements and monitoring",
            },
        }

    def _assess_business_impact(self, message: AgentMessage) -> str:
        """Assess business impact of findings."""
        if (
            "security" in message.sender.lower()
            or "vulnerability" in message.content.lower()
        ):
            return "HIGH: Security risks affect user trust and regulatory compliance"
        elif (
            "performance" in message.sender.lower() or "slow" in message.content.lower()
        ):
            return "HIGH: Performance impacts conversion rates and search rankings"
        elif (
            "accessibility" in message.sender.lower()
            or "wcag" in message.content.lower()
        ):
            return "MEDIUM: Accessibility issues create legal compliance risk and exclude users"
        else:
            return "MEDIUM: Quality issues affect user experience and brand perception"

    def _extract_domains(self, content: str) -> list[str]:
        """Extract domains mentioned in message content."""
        domain_keywords = {
            "Security": ["security", "vulnerability", "SSL", "header", "attack"],
            "Performance": ["performance", "speed", "loading", "vitals"],
            "Accessibility": ["accessibility", "WCAG", "alt", "contrast"],
            "Visual": ["visual", "design", "color", "layout", "image"],
            "SEO": ["SEO", "meta", "title", "search"],
            "Content": ["content", "text", "readability", "language"],
        }

        mentioned_domains = []
        content_lower = content.lower()

        for domain, keywords in domain_keywords.items():
            if any(keyword.lower() in content_lower for keyword in keywords):
                mentioned_domains.append(domain)

        return mentioned_domains

    def _determine_domain(self, agent_name: str) -> str:
        """Determine domain from agent name."""
        domain_map = {
            "SicherheitsZwerg": "Security",
            "LeistungsZwerg": "Performance",
            "ZugaenglichkeitsZwerg": "Accessibility",
            "VisualZwerg": "Visual",
            "SEOZwerg": "SEO",
            "InhaltZwerg": "Content",
            "WebBrowserZwerg": "Browser",
            "KommanderZwerg": "Strategy",
        }
        return domain_map.get(agent_name, "General")

    def _estimate_effort(self, action: str) -> str:
        """Estimate implementation effort for actions."""
        high_effort_keywords = ["architecture", "redesign", "comprehensive", "system"]
        medium_effort_keywords = ["optimize", "implement", "configure", "update"]

        action_lower = action.lower()

        if any(keyword in action_lower for keyword in high_effort_keywords):
            return "HIGH (2-4 weeks)"
        elif any(keyword in action_lower for keyword in medium_effort_keywords):
            return "MEDIUM (3-7 days)"
        else:
            return "LOW (1-2 days)"
