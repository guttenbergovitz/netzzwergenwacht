# 0012. TUI Application State and Asynchronous Execution

## Status

Accepted

## Context

Terminal user interfaces that mix blocking I/O, unstructured shared mutable state, and rendering logic suffer from frozen screens during network or browser collection, race conditions during cancellation, and corrupted terminal states if an error or panic occurs while raw mode is active.

We need a predictable concurrency and state management model for Zwergenleitstand that integrates cleanly with Tokio, supports deterministic unit testing without a TTY, and guarantees terminal restoration.

## Decision

1. **Unidirectional Elm/Reducer architecture (`Action` -> `reduce(&mut AppState, Action)` -> `Vec<Effect>`)**:
   - All terminal key events, timer ticks, diagnostic engine events (`DiagnosticEvent`), and background task completions are translated into a single typed `AppAction` enum.
   - A pure, synchronous reducer (`src/tui/reducer.rs`) mutates `AppState` and returns declarative `AppEffect` commands (such as `StartRun`, `CancelRun`, `LoadReport`, `LoadHistory`, `SaveReport`, `Quit`).
   - Rendering (`src/tui/views/`) is a pure function `render(frame: &mut Frame, state: &AppState)` that never performs network, subprocess, filesystem, or LLM I/O.
2. **Separated diagnostic domain storage and transient UI state**:
   - `AppState` holds shared, immutable references (`Arc<EvidenceSnapshot>`, `Arc<AuditReport>`, `Option<Arc<InvestigationOutcome>>`, `Option<Arc<PatrolReport>>`) once produced or loaded, rather than cloning evidence payloads across views.
   - Transient presentation state (active view, focus pane, table cursors, filter predicates, sort keys, scroll offsets, modal state, bounded recent-event ring buffer) lives in lightweight view-state structs.
3. **Background diagnostic tasks with cooperative cancellation**:
   - Diagnostic runs execute on background Tokio tasks spawned by the effect runner (`src/tui/runtime.rs`).
   - Each active run holds a cancellation handle (`tokio::sync::watch::Sender<bool>` plus task `AbortHandle`). When the operator presses `c` (or `Ctrl+C`), the runtime transitions run state to `Cancelling`, signals the watch channel, and aborts the background task, triggering RAII process-group termination (`kill -9 -<pgid>`) on any active Chromium/Lighthouse/axe subprocess.
4. **RAII Terminal Lifecycle Guard (`TerminalGuard`)**:
   - Entering raw mode and the alternate screen is encapsulated in a `TerminalGuard` struct whose `Drop` implementation disables raw mode, leaves the alternate screen, and restores cursor visibility.
   - A panic hook restores terminal state before delegating to the default panic handler, ensuring the user's shell is never left corrupted.
5. **Bounded render loop**:
   - The event loop redraws on user input, batch-drained diagnostic events, or a modest tick interval (250 ms when a run is active to update elapsed timers; idle until input when exploring static data), avoiding busy loops and unnecessary CPU usage.

## Consequences

- Every state transition, filter, sort, navigation action, and lifecycle edge case can be tested deterministically in fast unit tests by feeding `AppAction` values into `reduce` and rendering to Ratatui's `TestBackend`.
- Background collection and analysis cannot freeze keyboard navigation or frame rendering.
- Terminal state is reliably restored across normal exits, errors, and cancellations.
