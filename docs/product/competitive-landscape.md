# Competitive Landscape and Positioning

This document records verified observations from public documentation of reference tools and summarises architectural lessons for `NetzZwergenWacht`. Competitive differentiation claims remain hypotheses to be validated through practical benchmarks.

## 1. Reference Products

| Product | Verified Capabilities (Public Docs) | Lessons Adopted by NZW | NZW Differentiation Hypothesis |
|---|---|---|---|
| **SquirrelScan** (`docs.squirrelscan.com`) | Audit profiles (`quick` 25p / `surface` 100p / `full` 500p), smart rate-limit backoff (marks `429`/`503` as unverifiable rather than broken), caching-aware re-crawls, 300+ ranked rules including Agent Experience (`llms.txt`, `AGENTS.md`), `--format llm` for coding agents. | Explicit audit profiles, marking rate-limited/skipped checks as unverifiable, machine-readable LLM/agent outputs, Agent Experience as a domain. | Autonomous hypothesis-driven investigation and stakeholder-oriented decision briefs rather than rule-count-driven crawling. |
| **Sitebulb** (`sitebulb.com`) | Context-sensitive prioritised hints, page-level evidence association, crawl/directory structure analysis, representative sampling. | Findings must carry context, significance, and affected-page provenance rather than raw metrics. | Open-source CLI/library + agentic cross-domain reasoning rather than a desktop-only SEO crawler. |
| **Silktide** (`silktide.com`) | Digital quality governance, clustering repeated defects into systemic/template issues, portfolio-level tracking. | Cluster repeated findings (e.g. 300 missing attributes from one shared component) into systemic remediation opportunities. | Lightweight self-hosted execution without heavyweight enterprise SaaS lock-in. |
| **Siteimprove** (`siteimprove.com`) | Organisational quality objectives, accessibility governance, responsibility assignment, verified fix tracking. | Configurable quality objectives and explicit verification of completed fixes. | Developer- and PM-friendly open-source workflow with transparent local/BYO-LLM control. |
| **Sitelemetry** (`sitelemetry.com`) | MCP server delivering structured multi-pillar evidence (security, SEO, AI visibility, accessibility, performance) to coding agents; `localhost` support; SARIF CI output. | Serve both human stakeholders and external coding agents (JSON schemas, future MCP interface). | Built-in `KommandantZwerg` investigation loop for non-technical stakeholders (PM/PO/CTO), not only an MCP data feed for IDE agents. |

## 2. Specialist Measurement Engines (Reuse Policy)

Rather than reimplementing mature engines in Rust, NZW integrates established standards behind typed adapter contracts with version provenance:

- **Lighthouse** (Core Web Vitals & performance diagnostics)
- **axe-core** (rendered-DOM accessibility rules)
- **Chromium DevTools Protocol (CDP)** (runtime console/network/layout observations)
- **`rustls` / `x509-parser`** (TLS handshake and certificate inspection)
