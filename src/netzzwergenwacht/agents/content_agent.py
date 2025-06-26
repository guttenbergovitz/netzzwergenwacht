"""Content Expert Agent for CrewAI integration."""

from crewai import Agent
from langchain_core.language_models import BaseChatModel


class ContentExpertAgent:
    """Content Expert Agent for CrewAI integration."""

    def __init__(self, llm: BaseChatModel):
        self.llm = llm

    def create_agent(self) -> Agent:
        return Agent(
            role="Senior Content Strategist",
            goal="Analyze website content for quality, readability, and effectiveness, providing improvement strategies",
            backstory="""You are a content expert with a strong understanding of readability metrics,
            content structure, language quality, and user engagement. You can identify duplicate content,
            assess content freshness, and provide recommendations for improving overall content quality.""",
            llm=self.llm,
            verbose=True,
            allow_delegation=False,
            max_iter=3,
        )
