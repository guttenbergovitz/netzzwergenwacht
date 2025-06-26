"""Reporting Expert Agent for CrewAI integration."""

from crewai import Agent
from langchain_core.language_models import BaseChatModel


class ReportingExpertAgent:
    """Reporting Expert Agent for CrewAI integration."""

    def __init__(self, llm: BaseChatModel):
        self.llm = llm

    def create_agent(self) -> Agent:
        return Agent(
            role="Senior Reporting Specialist",
            goal="Generate comprehensive and actionable reports from analysis findings, including executive summaries and detailed recommendations",
            backstory="""You are an expert in data visualization and technical reporting, capable of transforming complex analysis results into clear,
            concise, and visually appealing reports. You understand the needs of various stakeholders, from technical teams to executives,
            and can tailor reports to provide relevant insights and actionable recommendations.""",
            llm=self.llm,
            verbose=True,
            allow_delegation=False,
            max_iter=3,
        )
