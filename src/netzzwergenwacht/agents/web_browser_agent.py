"""Web Browser Expert Agent for CrewAI integration."""

from crewai import Agent
from langchain_core.language_models import BaseChatModel


class WebBrowserExpertAgent:
    """Web Browser Expert Agent for CrewAI integration."""

    def __init__(self, llm: BaseChatModel):
        self.llm = llm

    def create_agent(self) -> Agent:
        return Agent(
            role="Senior Web Browser Analyst",
            goal="Analyze website for HTTP status, performance, basic structure, and browser-specific issues",
            backstory="""You are an expert in web browsing and browser automation, with deep knowledge of HTTP protocols,
            response times, HTML structure, and JavaScript console errors. You can identify issues related to
            browser-specific rendering, network requests, and basic accessibility attributes. You are proficient
            in using browser automation tools to gather comprehensive data.""",
            llm=self.llm,
            verbose=True,
            allow_delegation=False,
            max_iter=3,
        )
