"""Rule Engine Expert Agent for CrewAI integration."""

from crewai import Agent
from langchain_core.language_models import BaseChatModel


class RuleEngineExpertAgent:
    """Rule Engine Expert Agent for CrewAI integration."""

    def __init__(self, llm: BaseChatModel):
        self.llm = llm

    def create_agent(self) -> Agent:
        return Agent(
            role="Senior Rule Engine Specialist",
            goal="Design, implement, and manage custom analysis rules to extend the system's capabilities and enforce specific quality standards",
            backstory="""You are an expert in rule-based systems and custom logic implementation. You can translate complex business requirements
            and technical specifications into executable rules, ensuring the system can adapt to evolving analysis needs and provide highly tailored insights.
            You are proficient in defining rule sets, managing rule conflicts, and optimizing rule execution for efficiency.""",
            llm=self.llm,
            verbose=True,
            allow_delegation=False,
            max_iter=3,
        )
