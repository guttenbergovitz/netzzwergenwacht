# 0015. TUI Visual Language and Terminal Accessibility

## Status

Accepted

## Context

Zwergenleitstand must serve as a high-density technical investigation console across diverse terminal environments (true-colour macOS/Linux terminals, 16/256-colour SSH sessions, `NO_COLOR` / monochrome accessibility setups, and varying viewport dimensions) while expressing the restrained identity of **Die Zwergenbrigade** (*Kleine Zwerge. Große Sorgfalt.*).

## Decision

1. **Semantic theme tokens (`src/tui/theme.rs`) with automatic `NO_COLOR` and monochrome support**:
   - Widgets reference semantic styles (`theme.header()`, `theme.border_focused()`, `theme.border_unfocused()`, `theme.selected_row()`, `theme.severity(sev)`, `theme.status(state)`, `theme.muted()`, `theme.accent()`) rather than hard-coded RGB values.
   - Support three selectable theme modes (`Standard Dark`, `High Contrast`, and `Monochrome`), automatically defaulting to `Monochrome` when the `NO_COLOR` environment variable is set or `TERM=dumb`.
   - Use ANSI / indexed terminal colours that degrade gracefully across 16-colour, 256-colour, and true-colour terminals, with warm amber/yellow accents (`Color::Yellow`) for brigade focus headers, cyan (`Color::Cyan`) for active operations, green (`Color::Green`) for completed/passing states, and red (`Color::Red`) for critical/failed states.
2. **Textual markers mandatory alongside colour**:
   - Severity is always rendered with fixed-width textual badges (`[CRIT]`, `[HIGH]`, `[MED ]`, `[LOW ]`, `[INFO]`) so severity remains immediately scannable in monochrome mode and for colour-blind operators.
   - Operational states always render explicit uppercase text tokens (`DONE`, `RUNNING`, `QUEUED`, `WAITING`, `PARTIAL`, `SKIPPED`, `FAILED`, `BLOCKED`, `CANCELLED`, `UNKNOWN`).
   - Focused panels and selected rows use both border/style emphasis and an explicit ASCII/Unicode cursor prefix (`>` or `▸`) plus `[FOCUSED]` panel title indicators in monochrome mode.
3. **Unicode with ASCII fallback**:
   - Support an ASCII border/symbol mode (`--ascii` or runtime toggle) that replaces Unicode box-drawing and block characters (`█`) with standard ASCII (`+`, `-`, `|`, `#`, `>`) for restricted terminal fonts.
4. **Full keyboard accessibility and input mode separation**:
   - Every view, sub-tab, master-detail split, filter input, sort selector, and modal dialog is operable purely via keyboard:
     - `1`–`9` for direct view selection; `Tab` / `Shift+Tab` for panel focus cycling; `[` / `]` for sub-tab switching.
     - `j`/`k` or `Down`/`Up` for row navigation; `g`/`G` for first/last item; `PageUp`/`PageDown` for paging.
     - `Enter` to inspect, follow an `EvidenceRef`, or activate; `Esc` to close modals or step back.
     - `/` to enter search/filter text mode (suspending single-key global shortcuts while typing until `Enter` or `Esc` is pressed).
     - `s` to cycle deterministic sort order; `m` to cycle theme/monochrome mode; `c` to cancel an active run; `?` to toggle context-sensitive help; `q` to request exit.
   - The bottom status bar always displays active mode, run state, and context-relevant keybindings.

## Consequences

- Zwergenleitstand remains legible and accessible in colour, high-contrast, monochrome (`NO_COLOR`), and ASCII-only terminals.
- Operators never lose track of keyboard focus or trigger accidental global actions while typing a URL or filter query.
