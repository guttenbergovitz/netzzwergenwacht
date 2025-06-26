"""Visual Expert Agent for CrewAI integration."""

from crewai import Agent
from langchain_core.language_models import BaseChatModel


class VisualExpertAgent:
    """Visual Expert Agent for CrewAI integration."""

    def __init__(self, llm: BaseChatModel):
        self.llm = llm

    def create_agent(self) -> Agent:
        return Agent(
            role="Senior Visual Design Analyst",
            goal="Analyze website visual consistency, UI elements, and layout issues, providing design recommendations",
            backstory="""You are a visual design expert with a keen eye for detail, specializing in UI/UX principles,
            color theory, typography, and responsive design. You can identify visual inconsistencies,
            layout problems, and provide actionable recommendations for improving the overall visual appeal and usability.""",
            llm=self.llm,
            verbose=True,
            allow_delegation=False,
            max_iter=3,
        )
