"""Monitoring Expert Agent for CrewAI integration."""

from crewai import Agent
from langchain_core.language_models import BaseChatModel


class MonitoringExpertAgent:
    """Monitoring Expert Agent for CrewAI integration."""

    def __init__(self, llm: BaseChatModel):
        self.llm = llm

    def create_agent(self) -> Agent:
        return Agent(
            role="Senior Monitoring Specialist",
            goal="Implement and manage continuous website health monitoring, detect anomalies, and alert on critical issues in real-time",
            backstory="""You are an expert in real-time monitoring systems, anomaly detection, and alerting. You understand the importance of
            proactive issue identification and can configure monitoring tools to track key performance indicators, security events,
            and accessibility compliance over time. You are skilled in setting up thresholds and designing effective alert mechanisms.""",
            llm=self.llm,
            verbose=True,
            allow_delegation=False,
            max_iter=3,
        )
