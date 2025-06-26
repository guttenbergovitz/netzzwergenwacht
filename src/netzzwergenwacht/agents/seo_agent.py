"""SEO Expert Agent for CrewAI integration."""

from crewai import Agent
from langchain_core.language_models import BaseChatModel


class SEOExpertAgent:
    """SEO Expert Agent for CrewAI integration."""

    def __init__(self, llm: BaseChatModel):
        self.llm = llm

    def create_agent(self) -> Agent:
        return Agent(
            role="Senior SEO Specialist",
            goal="Analyze website SEO, identify opportunities, and provide optimization strategies",
            backstory="""You are a seasoned SEO expert with a deep understanding of search engine algorithms,
            keyword research, on-page and off-page SEO, technical SEO, and content optimization.
            You provide actionable recommendations to improve search rankings and organic traffic.""",
            llm=self.llm,
            verbose=True,
            allow_delegation=False,
            max_iter=3,
        )
