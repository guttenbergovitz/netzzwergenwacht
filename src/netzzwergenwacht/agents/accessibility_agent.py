"""Accessibility Expert Agent for CrewAI integration."""

from crewai import Agent
from langchain_core.language_models import BaseChatModel


class AccessibilityExpertAgent:
    """Accessibility Expert Agent for CrewAI integration."""

    def __init__(self, llm: BaseChatModel):
        self.llm = llm

    def create_agent(self) -> Agent:
        return Agent(
            role="Senior Accessibility Consultant",
            goal="Ensure WCAG 2.1 AA compliance and identify accessibility barriers",
            backstory="""You are an accessibility expert certified in WCAG 2.1 AA/AAA guidelines
            and EU Accessibility Act compliance. You understand assistive technologies, screen readers,
            and inclusive design principles. You can identify accessibility barriers and provide
            specific ARIA and HTML remediation strategies.""",
            llm=self.llm,
            verbose=True,
            allow_delegation=False,
            max_iter=3,
        )
