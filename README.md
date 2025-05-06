# Netz Zwergen Wacht


## Overall Direction & Vision:

NetzZwergenWacht aims to be an intelligent, automated system for analyzing and monitoring the quality of websites. It will employ "Dwarfs" – LLM-powered software agents – to proactively perform checks, identify issues, and report on the health and standards of web applications. The goal is to provide actionable insights to development teams and stakeholders, helping to maintain and improve web quality efficiently.

## Core Functional Areas:

* Automated End-to-End (E2E) Interaction: Dwarfs will navigate websites, simulating user journeys to check core functionalities and user flows.
* Surface-Level Quality Analysis: Dwarfs will inspect websites for common technical and usability issues, such as broken links, console errors, basic SEO hygiene, and fundamental accessibility aspects. 
* LLM-Powered Intelligence: Large Language Models will be integrated to enable Dwarfs to understand context, interpret findings, classify the severity of issues, and potentially generate human-readable summaries or suggestions. 
* Reporting and Alerting: The system will generate clear reports detailing discovered issues and will be capable of sending alerts for critical problems. 
* Configurable & Scheduled Monitoring: Users will be able to configure which websites the Dwarfs monitor and how frequently these checks are performed.

## Key Technology Choices (Initial):

Primary Language: Python 
Project & Dependency Management: uv
Browser Automation: Playwright
(Future): Specific LLM APIs, databases, UI frameworks as needed.

## High-Level Task List / Iterative Development Steps:

### Phase 0: 
#### Foundation & Setup
1.  ~~Set up the Git repository on GitHub.~~
2.  ~~Initialize the project using uv (uv init).~~
3.  ~~Create an initial .gitignore file.~~
4.  ~~Draft a basic README.md (or use this document as a starting point).~~
5.  ~~Establish the main branch (main) and a development branch (develop).~~

### Phase 1: 
#### Core Browser Interaction ("Dwarf's First Steps")
1.  Integrate the Playwright library for browser automation (uv add playwright).
2.  Install necessary browser binaries (uv run playwright install).
3.  Develop core functions/classes for a "Browser Dwarf" to:
    a.  Launch and manage a browser instance.
    b.  Open a specified URL in a browser page.
    c.  Retrieve basic page information (e.g., page title).
    d.  Properly close the browser and page.
4.  Create a simple command-line interface (CLI) script (e.g., main.py) to trigger these actions for a user-provided URL.
5.  Implement basic error handling for browser operations.

### Phase 2: 
#### Basic Surface Checks ("Dwarf's Inspection Tools")
1.  Develop functionality for the Browser Dwarf to detect broken links (4xx, 5xx status codes) on a given page.
2.  Implement functionality to capture and identify JavaScript errors from the browser's console.
3.  Extend the CLI to run these specific checks.
4.  Implement basic reporting of findings (e.g., print to console, output to a simple text file).

### Phase 3: 
#### LLM Integration ("Dwarf Gains Intelligence")
1.  Research and select an initial LLM provider and API.
2.  Implement a module to securely connect to and interact with the chosen LLM API.
3.  Design prompts for the LLM to:
    a.  Analyze collected data (e.g., list of broken links, console errors).
    b.  Classify the type or potential severity of identified issues.
4.  Integrate LLM calls into the workflow: send data, receive and process LLM insights.
5.  Update reporting to include LLM-generated classifications or summaries.

### Phase 4: 
#### Enhanced Reporting & Actions ("Dwarf's Report & Alerts")
1.  Develop a more structured reporting format (e.g., JSON, HTML, or Markdown).
2.  Include more details in reports: URLs, issue descriptions, evidence (e.g., error messages), LLM insights.
3.  Implement a basic notification system (e.g., email alerts for critical issues found).

### Phase 5: 
#### Configuration, Scheduling & Usability ("Dwarf's Mission Control")
1.  Refine the CLI for better usability (e.g., using Typer or Click).
2.  Allow users to configure:
    a.  A list of target websites/URLs to monitor.
    b.  Types of checks to perform for each target.
3.  Implement a basic scheduling mechanism for running checks periodically (could be OS-level cron initially, or an in-app scheduler later).
4.  (Optional for early phases) Explore a very simple web UI for basic interaction if the CLI becomes limiting.

### Phase X: 
#### Advanced Features & Refinements (Future Direction)
1.  Deeper Analysis:
    a.  More comprehensive accessibility checks (e.g., against WCAG guidelines).
    b.  Basic SEO analysis (meta tags, heading structure, keyword presence - with LLM help).
    c.  Collection of basic performance metrics (e.g., page load time).
    d.  (Advanced) Visual regression testing, potentially aided by multimodal LLMs.
2.  Workflow & Integrations:
    a.  Integration with CI/CD pipelines to check websites post-deployment.
    b.  Integration with issue tracking systems (e.g., JIRA, GitHub Issues) to automatically create tickets.
3.  User Experience & Management:
    a.  Develop a more comprehensive web dashboard for viewing results, trends, and managing monitored sites.
    b.  Allow users to define custom test scenarios or user journeys for E2E checks.
    c.  Implement user authentication and management if deployed as a shared service.
4.  Scalability & Reliability:
    a.  Optimize for handling multiple concurrent checks.
    b.  Improve error handling and resilience of the "Dwarfs".
    c.  Database integration for storing results, configurations, and historical data.