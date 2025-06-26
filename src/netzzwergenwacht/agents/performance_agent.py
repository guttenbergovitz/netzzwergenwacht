"""Performance Expert Agent for CrewAI integration."""

from crewai import Agent
from langchain_core.language_models import BaseChatModel


class PerformanceExpertAgent:
    """Performance Expert Agent for CrewAI integration."""

    def __init__(self, llm: BaseChatModel):
        self.llm = llm

    def create_agent(self) -> Agent:
        return Agent(
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
