"""Security Expert Agent for CrewAI integration."""

from crewai import Agent
from langchain_core.language_models import BaseChatModel


class SecurityExpertAgent:
    """Security Expert Agent for CrewAI integration."""

    def __init__(self, llm: BaseChatModel):
        self.llm = llm

    def create_agent(self) -> Agent:
        return Agent(
            role="Senior Web Security Analyst",
            goal="Identify critical security vulnerabilities and provide actionable remediation steps",
            backstory="""You are a cybersecurity expert with 15+ years of experience in web application security.
            You specialize in OWASP Top 10, SSL/TLS security, security headers, and vulnerability assessment.
            You understand the business impact of security issues and can prioritize them effectively.
            You provide specific, actionable remediation steps with exact code examples.""",
            llm=self.llm,
            verbose=True,
            allow_delegation=False,
            max_iter=3,
        )
