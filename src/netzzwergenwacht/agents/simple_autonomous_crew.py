"""Simple autonomous crew for testing the basic functionality."""

import os
from typing import Any

from crewai import Crew, Task
from crewai.agent import BaseAgent
from langchain_openai import ChatOpenAI

from ..dwarfs.base import ComprehensiveAnalysisReport
from ..utils.logging import get_logger
from .autonomous_communication import (
    communication_hub,
)
from .dokumentalist_zwerg import DokumentalistZwergAgent
from .kommander_zwerg import KommanderZwergAgent

logger = get_logger("simple_autonomous_crew")


class SimpleAutonomousCrew:
    """Simple autonomous multi-agent crew for testing."""

    def __init__(self, model: str = "gpt-4o-mini", temperature: float = 0.2):
        """Initialize the simple autonomous crew."""
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

        logger.info(f"🤖 Simple Autonomous CrewAI initialized with model: {model}")
        print("\n🎖️ Simple Autonomous NetzZwergenWacht Brigade Activating...")

    def create_simple_agents(self) -> None:
        """Create simple autonomous agents."""
        print("🔧 Assembling simple autonomous agents...")

        # Create command structure
        kommander_agent = self.kommander.create_agent()
        dokumentalist_agent = self.dokumentalist.create_agent()

        self.agents = [
            kommander_agent,  # 0 - Strategic command
            dokumentalist_agent,  # 1 - Documentation
        ]

        logger.info(f"✅ Created {len(self.agents)} simple autonomous agents")
        print(f"✅ {len(self.agents)} simple agents ready")

    def create_simple_tasks(self, report_data: dict[str, Any]) -> None:
        """Create simple tasks for testing."""
        print("\n🎖️ KommanderZwerg: Beginning simple strategic analysis...")

        # Clear previous communication history
        communication_hub.message_history.clear()
        communication_hub.active_tasks.clear()

        # KommanderZwerg analyzes findings
        self.kommander.analyze_initial_findings(report_data)

        # DokumentalistZwerg starts observing
        self.dokumentalist.observe_agent_conversations()

        # Create simple tasks
        command_task = Task(
            description=f"""As KommanderZwerg, analyze the website findings and provide strategic analysis.

            URL: {report_data.get("url", "N/A")}
            Total Issues Found: {report_data.get("total_issues", 0)}
            Critical Issues: {report_data.get("critical_issues", 0)}
            High Issues: {report_data.get("high_issues", 0)}

            Provide:
            1. Strategic overview of findings
            2. Priority recommendations
            3. Risk assessment
            4. Next steps for investigation
            """,
            agent=self.agents[0],  # KommanderZwerg
            expected_output="Strategic analysis with priority recommendations",
        )

        synthesis_task = Task(
            description="""As DokumentalistZwerg, synthesize the commander's strategic analysis
            into a comprehensive report.

            Create:
            1. Executive summary
            2. Key findings prioritization
            3. Recommended actions
            4. Implementation roadmap
            """,
            agent=self.agents[1],  # DokumentalistZwerg
            expected_output="Comprehensive analysis synthesis report",
            context=[command_task],
        )

        self.tasks = [command_task, synthesis_task]

        logger.info(f"✅ Created {len(self.tasks)} simple tasks")
        print(f"✅ {len(self.tasks)} simple tasks prepared")

    def analyze(self, report: ComprehensiveAnalysisReport) -> dict[str, Any]:
        """Execute simple autonomous analysis."""
        try:
            print("\n🚀 Launching Simple Autonomous Analysis...")
            print("=" * 50)

            self.create_simple_agents()
            report_data = self._prepare_simple_report_data(report)
            self.create_simple_tasks(report_data)

            # Create simple crew
            self.crew = Crew(
                agents=self.agents,
                tasks=self.tasks,
                verbose=True,
            )

            print("\n🎖️ Starting autonomous brigade operations...")
            print("💬 Communications:")
            print("-" * 40)

            # Execute analysis
            crew_result = self.crew.kickoff()

            print("\n" + "=" * 50)
            print("✅ Simple autonomous analysis completed!")

            return self._format_results(crew_result)

        except Exception as e:
            logger.error(f"❌ Simple autonomous analysis error: {e}")
            return {
                "success": False,
                "error": str(e),
                "analysis_type": "simple_autonomous_collaboration",
            }

    def _prepare_simple_report_data(
        self, report: ComprehensiveAnalysisReport
    ) -> dict[str, Any]:
        """Prepare simplified report data."""
        data = {
            "url": report.url,
            "total_issues": report.total_issues,
            "critical_issues": report.critical_issues,
            "high_issues": report.high_issues,
            "analysis_duration": report.analysis_duration_seconds,
            "security_issues": [],
            "performance_issues": [],
            "accessibility_issues": [],
        }

        # Extract simplified issues by category
        for result in report.dwarf_results:
            if not result.success:
                continue

            dwarf_type = result.dwarf_name.lower()

            issues_data = [
                {
                    "type": issue.issue_type,
                    "severity": issue.severity.value,
                    "description": issue.description,
                    "impact": issue.impact,
                }
                for issue in result.detailed_issues[:3]  # Limit to 3 issues per type
            ]

            if "security" in dwarf_type or "sicherheits" in dwarf_type:
                data["security_issues"] = issues_data
            elif "performance" in dwarf_type or "leistungs" in dwarf_type:
                data["performance_issues"] = issues_data
            elif "accessibility" in dwarf_type or "zugaenglichkeits" in dwarf_type:
                data["accessibility_issues"] = issues_data

        return data

    def _format_results(self, crew_result: Any) -> dict[str, Any]:
        """Format simple results."""
        # Get collaboration analysis
        collaboration_analysis = self.dokumentalist.analyze_collaboration_patterns()

        return {
            "success": True,
            "model": "Simple Autonomous CrewAI Brigade",
            "analysis": str(crew_result),
            "agent_count": len(self.agents),
            "task_count": len(self.tasks),
            "analysis_type": "simple_autonomous_collaboration",
            "agents_used": [agent.role for agent in self.agents],
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
