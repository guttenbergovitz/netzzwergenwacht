# Product Vision and Strategy

## 1. Authoritative Product Definition

> **NetzZwergenWacht** is an open-source, agentic web quality investigation system. A brigade of specialised diagnostic agents collaboratively investigates, measures and explains the reliability, security, accessibility, performance and overall quality of web applications.

> **Operational Mission (Autonomous Web Quality Patrol)**: NetzZwergenWacht autonomously patrols digital applications, learns their externally observable structure, identifies changes and emerging quality risks, selectively deploys specialist diagnostic agents and maintains evidence-backed institutional memory across recurring patrols.

**We are not building another website auditor. We are building a virtual team of website auditors.**

Deterministic collection and analysis are the essential **foundation** of NetzZwergenWacht, not the limit of its capabilities.

## 2. Explicit Non-Positioning

NetzZwergenWacht must **not** be positioned as:

- A replacement for engineering teams or human QA/accessibility specialists.
- An employee surveillance or personal-blame tool.
- A complete penetration testing platform.
- A legal compliance certification authority (automated checks never prove WCAG or EU Accessibility Act compliance).
- A generic SEO crawler, a Lighthouse wrapper, or a speculative chatbot.
- An autonomous system that modifies production applications.

## 3. Target Stakeholders & Jobs To Be Done

| Stakeholder | Core Questions | Required Outputs |
|---|---|---|
| **Project Manager** | Are we ready for release? What needs immediate attention vs what can wait? Were agreed fixes actually implemented? | Concise executive brief, prioritised action list, delivery/release risks, verification status, actionable tickets. |
| **Product Owner** | Do critical user journeys work reliably? Where is customer friction? Which fixes have the highest product value? | User-impact-oriented findings, journey assessments, backlog candidates with acceptance criteria and explicit uncertainty. |
| **CTO / Engineering Management** | Are we accumulating systemic quality debt? Which issues are architectural/template-level? How do applications compare over time? | Cross-domain correlations, systemic issue clusters, evidence-backed risk register, historical trends. |
| **SRE / QA / Technical Specialists** | Which observations support a finding? Can it be reproduced? What changed since the baseline? | Structured evidence artefacts, tool versions, reproduction steps, machine-readable JSON/SARIF, investigation traces. |

## 4. Operating Modes

1. **Autonomous Patrol (`nzw patrol`)** *(Flagship)*: Requires only a target URL. Discovers application topology and locales, retrieves institutional memory, plans stratified sampling, runs low-cost deterministic checks, escalates material anomalies selectively to `KommandantZwerg` and specialists, updates memory, and emits a change-oriented situation report.
2. **Deterministic Audit (`nzw check`)**: Runs configurable deterministic rules with zero LLM dependencies. Built for CI/CD quality gates, baselines, and offline/restricted environments.
3. **Agentic Investigation (`nzw investigate`)**: Explicitly commissioned specialist investigation where `KommandantZwerg` interprets stakeholder objectives, delegates typed diagnostic tools, formulates and tests falsifiable hypotheses, and produces stakeholder-ready reports.
4. **Verification Investigation (`nzw verify`)**: Re-investigates previously identified findings or remediation tasks and distinguishes confirmed resolution from missing or incomparable evidence.
