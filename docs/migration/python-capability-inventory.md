# Python Capability Inventory

This inventory audits the existing Python implementation on `main` (`src/netzzwergenwacht/`) and classifies every capability for the Rust rewrite:

- **Retain**: Core concept and requirements carried forward cleanly.
- **Redesign**: Useful capability whose architecture, contracts, or measurement methodology must be rebuilt.
- **Replace**: Custom heuristic/implementation replaced by an established external standard/engine.
- **Postpone**: Deferred to a later phase until core deterministic auditing is solid.
- **Remove**: Intentionally dropped defect, dead code, or misleading abstraction.

---

## 1. CLI & Orchestration (`cli/main.py`, `dwarfs/base.py`, `config/__init__.py`)

| Capability | Current Implementation | Classification | Notes / Findings |
|---|---|---|---|
| CLI entry point (`nzw`) | Typer + Rich (`check`, `analyze`, `version`, `config`) | **Retain** | Rebuild with `clap` + structured output. Keep `check` (fast/core) vs `analyze` (full) distinction only if backed by explicit audit profiles. |
| Configuration loading | Pydantic `BaseSettings` (`NZW_` env prefix, `.env`) | **Retain** | Replace with `serde` + TOML config + env overrides + validated domain types. |
| Orchestrator | `DwarfOrchestrator` using unbounded `asyncio.gather` | **Redesign** | Replace with `AuditOrchestrator` + `CollectionEngine` + bounded Tokio concurrency & execution budgets. |
| Dual `Issue` / `DetailedIssue` models | Separate basic and detailed pipelines per dwarf | **Remove** | Eliminate duplication. Produce one normalised `Finding` model; renderers choose verbosity/detail level. |
| `overall_score` calculation | `base.py:673` averages only `performance_metrics.performance_score` | **Remove** | Misleading aggregate score. Replace with domain-level pass/warn/fail counts and explicit policy gates. |

---

## 2. Dwarf Analysers (`src/netzzwergenwacht/dwarfs/`)

### 2.1 `WebBrowserZwerg` (`web_browser_zwerg.py`, 996 lines)
- **Retain**: HTTP status, redirect chain, response timing, console/network error capture, viewport/screenshot capture.
- **Redesign**:
  - Share a single collected HTTP + browser snapshot instead of launching `httpx.AsyncClient` (x2) and `async_playwright()` (x2) separately.
  - Fix event listener ordering (`page.on("console", ...)` and `page.on("requestfailed", ...)` were attached *after* `page.goto()`).
  - Remove incomplete `# TODO` placeholders from production paths.

### 2.2 `SicherheitsZwerg` (`sicherheits_zwerg.py`, 1,332 lines)
- **Retain**: HTTPS enforcement check, security headers (`HSTS`, `CSP`, `X-Frame-Options`, `X-Content-Type-Options`, `Referrer-Policy`, `Permissions-Policy`), TLS certificate validity/expiry/protocol inspection, cookie flags (`Secure`, `HttpOnly`, `SameSite`).
- **Redesign**:
  - Use collected HTTP response headers and `rustls` TLS handshake observations rather than 5 separate `httpx` clients and raw `ssl` sockets.
  - Gate active security checks (`nmap` port scanning, path probing) behind explicit `--active-scan` / authorised-target policy (`docs/architecture/security-model.md`).

### 2.3 `LeistungsZwerg` (`leistungs_zwerg.py`, 1,359 lines)
- **Replace**:
  - `httpx` `time.time()` delta (`page_load_time_ms`) is not real browser load performance.
  - `psutil.cpu_percent(interval=1)` measures local auditor CPU, not the target website (**Remove**).
  - Custom Core Web Vitals JS snippets -> **Replace** with **Lighthouse** adapter (with recorded Lighthouse version and execution status).
- **Retain**: Resource inventory (script/CSS/image counts, transfer sizes, compression headers `gzip`/`br`/`zstd`, caching headers).

### 2.4 `ZugaenglichkeitsZwerg` (`zugaenglichkeits_zwerg.py`, 2,457 lines)
- **Replace**:
  - Static BeautifulSoup heuristics for contrast, keyboard accessibility, focus management, ARIA, and forms -> **Replace** with **axe-core** executed against the rendered DOM in Chromium.
- **Remove**:
  - `eaa_compliance_score` and claims of "EU Accessibility Act compliance" / "WCAG 2.1 AA compliance" certification. Automated checks only detect a subset of machine-verifiable issues and must be labelled as such.
  - Duplicate `analyze()` vs `analyze_detailed()` methods (which drifted out of sync).

### 2.5 `SEOZwerg` (`seo_zwerg.py`, 1,035 lines)
- **Retain**: Title/meta description presence and length, canonical URL, `robots` meta / `robots.txt` / `sitemap.xml` presence, heading hierarchy (`h1`–`h6`), OpenGraph / Twitter Card tags, JSON-LD / structured data presence.
- **Redesign**: Consume shared `EvidenceSnapshot` (HTML + optional rendered DOM) instead of independent `httpx` calls.

### 2.6 `InhaltZwerg` (`inhalt_zwerg.py`, 1,683 lines)
- **Retain**: Word/character/sentence/paragraph counts, heading-to-content structure, basic readability metrics (explicitly labelled with algorithm & language assumptions), broken/empty link indicators, freshness metadata (`Last-Modified`, `<time>`, meta dates).
- **Redesign**: Extract clean text from shared DOM snapshot; separate measured text metrics from heuristic quality findings.

### 2.7 `VisualZwerg` (`visual_zwerg.py`, 1,860 lines)
- **Retain**: Viewport meta check, horizontal overflow detection, broken image detection (`naturalWidth == 0`), responsive screenshot capture across configured viewports.
- **Postpone**: Heuristic "visual consistency / color harmony / brand analysis" — defer until deterministic layout/overflow/asset integrity checks are rock solid.

---

## 3. Intelligence & Multi-Agent Layer (`llm/__init__.py`, `agents/`)

| Capability | Current Implementation | Classification | Notes / Findings |
|---|---|---|---|
| Structured LLM synthesis | `llm/__init__.py` (`OpenAIAnalyzer`) | **Redesign** | Keep as strictly optional post-analysis intelligence (correlation, remediation, executive summary) behind token/cost budgets and prompt-injection isolation. |
| CrewAI multi-agent hierarchy | `WorkingAutonomousCrew`, `KommanderZwergAgent`, `DokumentalistZwergAgent`, 7 expert agent wrappers, `AgentCommunicationHub` | **Remove** | Heavy dependency footprint (~260 packages), theatrical/print-based communication hub, no demonstrated advantage over a single structured LLM pipeline. Evaluate `rig-core` in Phase 4. |

---

## 4. Reporting & Persistence (`reporting/pdf_generator.py`, `cli/main.py`)

| Capability | Current Implementation | Classification | Notes / Findings |
|---|---|---|---|
| JSON export | Custom dict assembly in `cli/main.py` & `llm/__init__.py` | **Retain / Redesign** | Versioned, schema-validated JSON (`schemars`) as first-class output. |
| Terminal output | Rich tables & panels | **Retain** | Clean CLI summary; optional `ratatui` TUI only if justified later. |
| PDF reporting | `reportlab` / `weasyprint` (`pdf_generator.py`, 717 lines) | **Postpone** | Defer to later phase (or HTML/Markdown -> PDF outside core binary) to avoid heavy native PDF dependencies in core. |
| Audit history & regression | Not implemented | **Add (Phase 3)** | Persist `EvidenceSnapshot` / `AuditReport` as JSONL with stable finding fingerprints for regression diffing. |
