"""Autonomous agent communication system for multi-agent collaboration."""

from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any
from uuid import uuid4


class MessageType(Enum):
    """Types of messages agents can send."""

    REPORT = "REPORT"  # Agent reports findings to commander
    REQUEST = "REQUEST"  # Agent requests investigation from another agent
    SUGGESTION = "SUGGESTION"  # Agent suggests follow-up actions
    DELEGATION = "DELEGATION"  # Commander delegates tasks
    COLLABORATION = "COLLABORATION"  # Cross-agent collaboration
    SUMMARY = "SUMMARY"  # Final synthesis


class Priority(Enum):
    """Investigation priority levels."""

    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"


@dataclass
class AgentMessage:
    """Message between autonomous agents."""

    id: str = field(default_factory=lambda: str(uuid4()))
    sender: str = ""  # "SicherheitsZwerg"
    recipient: str = ""  # "KommanderZwerg" or specific agent
    message_type: MessageType = MessageType.REPORT
    content: str = ""  # Human-readable message content
    findings: dict[str, Any] = field(default_factory=dict)  # Structured data
    priority: Priority = Priority.MEDIUM
    timestamp: datetime = field(default_factory=datetime.now)
    requires_action: bool = False  # Does this message require follow-up?
    suggested_actions: list[str] = field(default_factory=list)

    def __str__(self) -> str:
        """Format message for display."""
        emoji = self._get_sender_emoji()
        priority_marker = (
            f"[{self.priority.value}] "
            if self.priority in [Priority.CRITICAL, Priority.HIGH]
            else ""
        )
        return f'{emoji} {self.sender}: "{priority_marker}{self.content}"'

    def _get_sender_emoji(self) -> str:
        """Get emoji for agent type."""
        emoji_map = {
            "KommanderZwerg": "🎖️",
            "SicherheitsZwerg": "🛡️",
            "LeistungsZwerg": "⚡",
            "ZugaenglichkeitsZwerg": "♿",
            "VisualZwerg": "🎨",
            "SEOZwerg": "🔍",
            "InhaltZwerg": "📝",
            "WebBrowserZwerg": "🌐",
            "DokumentalistZwerg": "📚",
        }
        return emoji_map.get(self.sender, "🤖")


@dataclass
class InvestigationTask:
    """Task assigned by commander to agents."""

    id: str = field(default_factory=lambda: str(uuid4()))
    assignee: str = ""
    task_description: str = ""
    context: dict[str, Any] = field(default_factory=dict)
    priority: Priority = Priority.MEDIUM
    dependencies: list[str] = field(
        default_factory=list
    )  # Other task IDs this depends on
    collaboration_with: list[str] = field(
        default_factory=list
    )  # Other agents to collaborate with
    deadline: datetime | None = None
    status: str = "ASSIGNED"  # ASSIGNED, IN_PROGRESS, COMPLETED, BLOCKED


class AgentCommunicationHub:
    """Central hub for agent-to-agent communication."""

    def __init__(self) -> None:
        self.message_history: list[AgentMessage] = []
        self.active_tasks: list[InvestigationTask] = []
        self.agent_states: dict[str, str] = {}  # agent_name -> current_status

    def send_message(self, message: AgentMessage) -> None:
        """Send message and add to history."""
        self.message_history.append(message)
        print(f"💬 {message}")  # Real-time display

    def get_messages_for_agent(self, agent_name: str) -> list[AgentMessage]:
        """Get all messages directed to specific agent."""
        return [msg for msg in self.message_history if msg.recipient == agent_name]

    def get_recent_findings(self, domain: str | None = None) -> list[AgentMessage]:
        """Get recent findings, optionally filtered by domain."""
        recent_reports = [
            msg
            for msg in self.message_history[-20:]
            if msg.message_type == MessageType.REPORT
        ]

        if domain:
            # Filter by domain keywords
            domain_keywords = {
                "security": ["security", "vulnerability", "attack", "SSL", "header"],
                "performance": ["performance", "speed", "loading", "metrics", "vitals"],
                "accessibility": [
                    "accessibility",
                    "WCAG",
                    "alt",
                    "contrast",
                    "screen reader",
                ],
                "visual": ["visual", "design", "color", "layout", "UI"],
                "seo": ["SEO", "meta", "title", "description", "structured"],
                "content": ["content", "readability", "text", "language", "duplicate"],
            }

            keywords = domain_keywords.get(domain.lower(), [])
            if keywords:
                recent_reports = [
                    msg
                    for msg in recent_reports
                    if any(
                        keyword.lower() in msg.content.lower() for keyword in keywords
                    )
                ]

        return recent_reports

    def assign_task(self, task: InvestigationTask) -> None:
        """Assign investigation task to agent."""
        self.active_tasks.append(task)
        self.agent_states[task.assignee] = "INVESTIGATING"

        # Send delegation message
        delegation_msg = AgentMessage(
            sender="KommanderZwerg",
            recipient=task.assignee,
            message_type=MessageType.DELEGATION,
            content=f"Investigate: {task.task_description}",
            findings={"task_context": task.context, "priority": task.priority.value},
            priority=task.priority,
            requires_action=True,
        )
        self.send_message(delegation_msg)

    def update_agent_status(self, agent_name: str, status: str) -> None:
        """Update agent's current status."""
        self.agent_states[agent_name] = status

    def get_collaboration_context(self, agent_name: str) -> dict[str, Any]:
        """Get relevant context for agent collaboration."""
        # Get related findings from other agents
        related_messages = []
        for msg in self.message_history:
            if msg.sender != agent_name and msg.message_type in [
                MessageType.REPORT,
                MessageType.SUGGESTION,
            ]:
                related_messages.append({
                    "agent": msg.sender,
                    "content": msg.content,
                    "findings": msg.findings,
                    "priority": msg.priority.value,
                })

        return {
            "related_findings": related_messages[-10:],  # Last 10 relevant findings
            "agent_states": self.agent_states,
            "active_investigations": [
                {
                    "task": task.task_description,
                    "assignee": task.assignee,
                    "status": task.status,
                }
                for task in self.active_tasks
            ],
        }


# Global communication hub instance
communication_hub = AgentCommunicationHub()
