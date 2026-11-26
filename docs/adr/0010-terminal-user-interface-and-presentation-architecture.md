# 0010. Terminal User Interface and Presentation Architecture

## Status

Accepted

## Context

NetzZwergenWacht produces rich diagnostic artefacts across deterministic checks (`AuditReport`), adaptive discovery (`CrawlSummary`), autonomous patrols (`PatrolReport`), historical comparisons (`RegressionReport`), and hypothesis-driven investigations (`InvestigationOutcome`, `EvidenceSnapshot`). Inspecting these artefacts exclusively through batch CLI text summaries or raw JSON/JSONL files forces operators to switch tools when correlating findings with underlying HTTP, TLS, DOM, timeline, and runtime evidence.

We need an interactive operator workbench (**Zwergenleitstand**) that runs locally without weakening the deterministic core, duplicating diagnostic rules, or requiring a separate web server stack.

Options considered:
1. **Ratatui + Crossterm local TUI** embedded in the `nzw` binary.
2. **Embedded HTTP server + browser SPA** (e.g. Axum + frontend bundle).
3. **External desktop GUI** (e.g. Tauri or egui).

## Decision

1. **Adopt `ratatui` (`0.30`) and `crossterm` (`0.29`) for the local interactive workbench (`Zwergenleitstand`)**:
   - Both crates are MIT-licensed, actively maintained, pure Rust, and compatible with our MSRV (`1.88`).
   - Prefer Ratatui's built-in widgets (`Table`, `List`, `Paragraph`, `Tabs`, `Gauge`, `BarChart`, `Sparkline`, `Block`, `Scrollbar`) over third-party widget dependencies unless a concrete gap is proven.
2. **Remain local-first without a daemon or web server**:
   - A terminal workbench operates over SSH, inside containers, and on developer workstations without opening listening sockets, managing TLS/CORS for a local UI server, or shipping a JavaScript frontend build pipeline.
   - Future standalone HTML reports will be static, self-contained documents generated from serialized `AuditReport` / `PatrolReport` artefacts rather than a live server.
3. **Enforce strict separation between diagnostic engine, persistence, and presentation**:
   - `src/tui/` is purely a consumer of application services (`collection`, `analysis`, `investigation`, `patrol`, `persistence`), offline evidence queries (`src/investigation/evidence_query.rs`, `src/investigation/browser_timeline.rs`), and the diagnostic event stream (`src/events.rs`).
   - `src/tui/` must never implement diagnostic rules, invoke HTTP or browser adapters directly without going through engine services, or mutate diagnostic truth.
   - All existing headless CLI commands (`check`, `batch`, `validate`, `diff`, `investigate`, `verify`, `patrol`, `report`) and JSON/JSONL/Markdown output contracts remain first-class and unchanged.
4. **Provide a dedicated `nzw tui` subcommand**:
   - `nzw tui` launches the interactive workbench (entering the Launcher when no target or artefact is supplied, immediately starting or pre-populating a target when a URL or `--targets` is supplied, or opening offline exploration when `--report` or `--history` is supplied).
   - Keeping interactive TUI execution under `nzw tui` avoids polluting headless automation commands (`nzw check`, `nzw patrol`, `nzw investigate`) with terminal raw-mode side effects.

## Consequences

- Operators gain an immediate, single-binary investigation console over live runs and saved reports without a browser or server daemon.
- Headless CI/CD pipelines continue to use `nzw check`, `nzw diff`, `nzw verify`, and `nzw patrol` with zero TUI overhead.
- All presentation state lives in `src/tui/`, keeping `domain`, `collection`, `analysis`, `investigation`, `patrol`, and `persistence` free of terminal dependencies.
