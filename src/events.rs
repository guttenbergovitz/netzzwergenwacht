//! Unified diagnostic event model and bounded event transport.
//!
//! Connects collection, deterministic analysis, adaptive discovery, autonomous
//! patrols, and agentic investigations to interactive consumers such as
//! **Zwergenleitstand** (`src/tui/`) without coupling engine execution speed
//! to rendering or allocating unbounded queues.

use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Instant;

use serde::{Deserialize, Serialize};
use tokio::sync::mpsc;

use crate::brigade::DwarfId;
use crate::domain::{Confidence, Severity};
use crate::investigation::InvestigationEvent;

/// Default bounded capacity for diagnostic event channels.
pub const DEFAULT_EVENT_CHANNEL_CAPACITY: usize = 256;

/// Identifies a single diagnostic execution session.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct RunId(pub String);

impl RunId {
    /// Creates a new run identifier.
    #[must_use]
    pub fn new(id: impl Into<String>) -> Self {
        Self(id.into())
    }

    /// Returns the string slice of this run identifier.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// Bounded receiver for diagnostic events emitted during a run.
pub type DiagnosticEventReceiver = mpsc::Receiver<DiagnosticEvent>;

/// Creates a bounded diagnostic event channel with [`DEFAULT_EVENT_CHANNEL_CAPACITY`].
#[must_use]
pub fn diagnostic_event_channel(run_id: RunId) -> (DiagnosticEventSink, DiagnosticEventReceiver) {
    DiagnosticEventSink::bounded(run_id.0, DEFAULT_EVENT_CHANNEL_CAPACITY)
}

impl std::fmt::Display for RunId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

/// Identifies a diagnostic evidence collector.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CollectorId {
    /// Level 1 HTTP transport and header/body acquisition.
    Http,
    /// Level 1 TLS handshake and certificate chain inspection.
    Tls,
    /// Level 2 headless Chromium runtime and CDP collection.
    Browser,
    /// Level 2 Lighthouse performance and laboratory metrics.
    Lighthouse,
    /// Level 2 axe-core rendered accessibility audit.
    Axe,
    /// Adaptive crawler and sitemap discovery.
    Discovery,
}

impl CollectorId {
    /// Short display label for operator views.
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::Http => "HTTP",
            Self::Tls => "TLS",
            Self::Browser => "Browser",
            Self::Lighthouse => "Lighthouse",
            Self::Axe => "axe-core",
            Self::Discovery => "Discovery",
        }
    }
}

/// Execution mode for a diagnostic run.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DiagnosticRunMode {
    /// Deterministic Level 1 / Level 2 audit without LLM dependencies.
    DeterministicCheck,
    /// Hypothesis-driven investigation coordinated by `KommandantZwerg`.
    AgenticInvestigation,
    /// Single-application or portfolio autonomous patrol.
    AutonomousPatrol,
    /// Offline exploration of a saved report or historical JSONL log.
    OfflineExploration,
}

impl DiagnosticRunMode {
    /// Human-readable British English label.
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::DeterministicCheck => "Deterministic check",
            Self::AgenticInvestigation => "Agentic investigation",
            Self::AutonomousPatrol => "Autonomous patrol",
            Self::OfflineExploration => "Offline exploration",
        }
    }
}

/// Contextual coordinates attaching a [`DiagnosticEvent`] to a target, page,
/// collector, or specialist dwarf.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct EventContext {
    /// Canonical target or application identifier.
    pub target: Option<String>,
    /// Specific page URL being inspected.
    pub page: Option<String>,
    /// Active collector when the event originates from data acquisition.
    pub collector: Option<CollectorId>,
    /// Active specialist when the event originates from a dwarf analyser or agent.
    pub dwarf: Option<DwarfId>,
    /// Optional operation or tool identifier.
    pub operation: Option<String>,
}

impl EventContext {
    /// Builds an empty context.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Attaches a target URL or identifier.
    #[must_use]
    pub fn with_target(mut self, target: impl Into<String>) -> Self {
        self.target = Some(target.into());
        self
    }

    /// Attaches a page URL.
    #[must_use]
    pub fn with_page(mut self, page: impl Into<String>) -> Self {
        self.page = Some(page.into());
        self
    }

    /// Attaches a collector identifier.
    #[must_use]
    pub const fn with_collector(mut self, collector: CollectorId) -> Self {
        self.collector = Some(collector);
        self
    }

    /// Attaches a dwarf identifier.
    #[must_use]
    pub const fn with_dwarf(mut self, dwarf: DwarfId) -> Self {
        self.dwarf = Some(dwarf);
        self
    }

    /// Attaches an operation or tool name.
    #[must_use]
    pub fn with_operation(mut self, operation: impl Into<String>) -> Self {
        self.operation = Some(operation.into());
        self
    }
}

/// Typed state transition or observation emitted during diagnostic execution.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum DiagnosticEventPayload {
    /// A diagnostic run has started.
    RunStarted {
        /// Operational mode selected for the run.
        mode: DiagnosticRunMode,
        /// Primary target or portfolio label.
        target: String,
    },
    /// A diagnostic run completed all scheduled work.
    RunCompleted {
        /// Human-readable completion summary.
        summary: String,
    },
    /// A diagnostic run completed with partial evidence or budget exhaustion.
    RunPartiallyCompleted {
        /// Explanation of which observations or budgets were incomplete.
        reason: String,
    },
    /// A diagnostic run failed before producing a usable outcome.
    RunFailed {
        /// Error message describing the failure.
        error: String,
    },
    /// A diagnostic run was cancelled by the operator or signal handler.
    RunCancelled {
        /// Cancellation reason.
        reason: String,
    },

    /// A candidate page or target was discovered or updated during crawling or sampling.
    TargetDiscovered {
        /// Discovered page URL.
        url: String,
        /// Crawl depth from the entry URL.
        depth: usize,
        /// Discovery mechanism (`"seed"`, `"sitemap"`, `"link"`, `"robots"`).
        source: String,
        /// Current inspection status (`"queued"`, `"completed"`, `"partial"`, `"failed"`, `"skipped"`).
        status: String,
    },

    /// A collector started acquiring evidence.
    CollectionStarted {
        /// Collector identifier.
        collector: CollectorId,
    },
    /// High-frequency collector progress update (eligible for coalescing).
    CollectionProgress {
        /// Collector identifier.
        collector: CollectorId,
        /// Units completed so far.
        completed_units: usize,
        /// Total known units, if bounded denominator is known.
        total_units: Option<usize>,
        /// Concise progress note.
        detail: String,
    },
    /// A collector captured complete or partial evidence within its scope.
    CollectionCompleted {
        /// Collector identifier.
        collector: CollectorId,
        /// Whether collection was partial (e.g. load timed out or truncated).
        partial: bool,
        /// Non-fatal warnings recorded during collection.
        warnings: Vec<String>,
    },
    /// A collector attempted acquisition and failed.
    CollectionFailed {
        /// Collector identifier.
        collector: CollectorId,
        /// Error explanation.
        error: String,
    },
    /// A collector was intentionally skipped.
    CollectionSkipped {
        /// Collector identifier.
        collector: CollectorId,
        /// Reason the collector did not run.
        reason: String,
    },

    /// A deterministic dwarf analyser started evaluating rules.
    AnalysisStarted {
        /// Specialist dwarf identifier.
        dwarf: DwarfId,
    },
    /// A deterministic dwarf analyser completed rule evaluation.
    AnalysisCompleted {
        /// Specialist dwarf identifier.
        dwarf: DwarfId,
        /// Total rules evaluated or considered.
        checks_total: usize,
        /// Rules that passed.
        checks_passed: usize,
        /// Rules that produced findings.
        checks_failed: usize,
        /// Rules skipped due to missing or inapplicable evidence.
        checks_skipped: usize,
        /// Rules that were inconclusive.
        checks_inconclusive: usize,
    },

    /// A deterministic or verified finding was recorded.
    FindingRecorded {
        /// Specialist dwarf that recorded the finding.
        dwarf: DwarfId,
        /// Stable rule identifier.
        rule_id: String,
        /// Finding title.
        title: String,
        /// Finding severity.
        severity: Severity,
        /// Finding confidence.
        confidence: Confidence,
    },

    /// An agentic specialist was activated during an investigation.
    SpecialistActivated {
        /// Specialist dwarf identifier.
        dwarf: DwarfId,
        /// Assigned focus or reason.
        focus: String,
    },
    /// `KommandantZwerg` proposed a diagnostic hypothesis.
    HypothesisProposed {
        /// Hypothesis identifier (e.g. `"hyp-1"`).
        hypothesis_id: String,
        /// Originating rule identifier.
        originating_rule: String,
        /// Candidate explanation statement.
        proposed_explanation: String,
        /// Tool requested to test the hypothesis.
        requested_tool: String,
    },
    /// `KommandantZwerg` evaluated a hypothesis against evidence.
    HypothesisEvaluated {
        /// Hypothesis identifier.
        hypothesis_id: String,
        /// Updated hypothesis lifecycle status label.
        status: String,
        /// Optional summary of the evaluation.
        summary: Option<String>,
    },

    /// A typed diagnostic tool was requested by `KommandantZwerg`.
    ToolRequested {
        /// Tool identifier.
        tool_id: String,
    },
    /// A typed diagnostic tool passed scope and budget authorisation.
    ToolAuthorised {
        /// Tool identifier.
        tool_id: String,
    },
    /// A typed diagnostic tool was rejected by scope or budget policy.
    ToolRejected {
        /// Tool identifier.
        tool_id: String,
        /// Rejection reason.
        reason: String,
    },
    /// A typed diagnostic tool completed execution.
    ToolCompleted {
        /// Tool identifier.
        tool_id: String,
        /// Whether usable evidence was collected.
        succeeded: bool,
        /// Concise execution summary.
        summary: String,
    },

    /// Resource budget consumption was updated.
    BudgetUpdated {
        /// LLM turns used so far.
        llm_turns_used: usize,
        /// Maximum configured LLM turns.
        max_llm_turns: usize,
        /// Tool calls used so far.
        tool_calls_used: usize,
        /// Maximum configured tool calls.
        max_tool_calls: usize,
        /// Elapsed wall-clock time in milliseconds.
        elapsed_ms: u64,
    },

    /// Non-fatal operational warning.
    Warning {
        /// Warning message.
        message: String,
    },
}

impl DiagnosticEventPayload {
    /// Returns `true` when this event is a high-frequency progress update that
    /// may be dropped/coalesced under channel backpressure without losing
    /// authoritative lifecycle transitions.
    #[must_use]
    pub const fn is_coalescable_progress(&self) -> bool {
        matches!(
            self,
            Self::CollectionProgress { .. } | Self::BudgetUpdated { .. }
        )
    }

    /// Short single-line summary for recent-activity feeds.
    #[must_use]
    pub fn short_description(&self) -> String {
        match self {
            Self::RunStarted { mode, target } => {
                format!("{} started for {target}", mode.label())
            }
            Self::RunCompleted { summary } => format!("Run completed: {summary}"),
            Self::RunPartiallyCompleted { reason } => {
                format!("Run partially completed: {reason}")
            }
            Self::RunFailed { error } => format!("Run failed: {error}"),
            Self::RunCancelled { reason } => format!("Run cancelled: {reason}"),
            Self::TargetDiscovered {
                url,
                source,
                status,
                ..
            } => format!("Target {url} ({source}: {status})"),
            Self::CollectionStarted { collector } => {
                format!("{} collection started", collector.label())
            }
            Self::CollectionProgress {
                collector, detail, ..
            } => format!("{}: {detail}", collector.label()),
            Self::CollectionCompleted {
                collector,
                partial,
                warnings,
            } => {
                if *partial {
                    format!(
                        "{} partial ({} warnings)",
                        collector.label(),
                        warnings.len()
                    )
                } else {
                    format!("{} captured", collector.label())
                }
            }
            Self::CollectionFailed { collector, error } => {
                format!("{} failed: {error}", collector.label())
            }
            Self::CollectionSkipped { collector, reason } => {
                format!("{} skipped: {reason}", collector.label())
            }
            Self::AnalysisStarted { dwarf } => {
                format!("{} started analysis", dwarf.display_name())
            }
            Self::AnalysisCompleted {
                dwarf,
                checks_total,
                checks_failed,
                ..
            } => format!(
                "{} completed ({checks_total} checks, {checks_failed} issues)",
                dwarf.display_name()
            ),
            Self::FindingRecorded {
                severity,
                rule_id,
                title,
                ..
            } => format!("[{severity:?}] {rule_id}: {title}"),
            Self::SpecialistActivated { dwarf, focus } => {
                format!("{} activated: {focus}", dwarf.display_name())
            }
            Self::HypothesisProposed {
                hypothesis_id,
                originating_rule,
                ..
            } => format!("{hypothesis_id} proposed ({originating_rule})"),
            Self::HypothesisEvaluated {
                hypothesis_id,
                status,
                ..
            } => format!("{hypothesis_id} evaluated: {status}"),
            Self::ToolRequested { tool_id } => format!("Tool {tool_id} requested"),
            Self::ToolAuthorised { tool_id } => format!("Tool {tool_id} authorised"),
            Self::ToolRejected { tool_id, reason } => {
                format!("Tool {tool_id} rejected: {reason}")
            }
            Self::ToolCompleted {
                tool_id, succeeded, ..
            } => format!(
                "Tool {tool_id} {}",
                if *succeeded { "completed" } else { "failed" }
            ),
            Self::BudgetUpdated {
                llm_turns_used,
                tool_calls_used,
                ..
            } => format!("Budget update: {llm_turns_used} LLM turns, {tool_calls_used} tool calls"),
            Self::Warning { message } => format!("Warning: {message}"),
        }
    }
}

/// Envelope for a single structured diagnostic event.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DiagnosticEvent {
    /// Run session identifier.
    pub run_id: RunId,
    /// Monotonically increasing per-run sequence number (1-based).
    pub sequence: u64,
    /// Elapsed milliseconds since the run started.
    pub elapsed_ms: u64,
    /// Cumulative number of coalescable progress events dropped due to channel backpressure.
    pub dropped_progress_events: u64,
    /// Cumulative number of non-progress events lost because the channel was full or closed.
    ///
    /// The value is sampled before the event is offered to the channel, so the envelope
    /// states how much of the stream is missing up to this point. Consumers use it to
    /// distinguish a complete stream from a truncated one.
    #[serde(default)]
    pub dropped_events: u64,
    /// Event coordinates.
    pub context: EventContext,
    /// Event payload.
    pub payload: DiagnosticEventPayload,
}

/// Shared state inside a [`DiagnosticEventSink`].
struct SinkInner {
    run_id: RunId,
    started_at: Instant,
    next_sequence: AtomicU64,
    dropped_progress: AtomicU64,
    dropped_events: AtomicU64,
    tx: Option<mpsc::Sender<DiagnosticEvent>>,
}

/// Bounded, cloneable event emitter passed to diagnostic services.
///
/// When created with [`DiagnosticEventSink::noop`], emissions perform no allocations
/// or channel operations.
#[derive(Clone)]
pub struct DiagnosticEventSink {
    inner: Arc<SinkInner>,
}

impl std::fmt::Debug for DiagnosticEventSink {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DiagnosticEventSink")
            .field("run_id", &self.inner.run_id)
            .field(
                "dropped_progress",
                &self.inner.dropped_progress.load(Ordering::Relaxed),
            )
            .field(
                "dropped_events",
                &self.inner.dropped_events.load(Ordering::Relaxed),
            )
            .finish_non_exhaustive()
    }
}

impl DiagnosticEventSink {
    /// Creates a bounded event channel pair `(sink, receiver)` with the specified capacity.
    #[must_use]
    pub fn bounded(
        run_id: impl Into<String>,
        capacity: usize,
    ) -> (Self, mpsc::Receiver<DiagnosticEvent>) {
        let cap = capacity.max(1);
        let (tx, rx) = mpsc::channel(cap);
        let sink = Self {
            inner: Arc::new(SinkInner {
                run_id: RunId::new(run_id),
                started_at: Instant::now(),
                next_sequence: AtomicU64::new(1),
                dropped_progress: AtomicU64::new(0),
                dropped_events: AtomicU64::new(0),
                tx: Some(tx),
            }),
        };
        (sink, rx)
    }

    /// Creates a no-op sink for headless executions that do not stream events.
    #[must_use]
    pub fn noop() -> Self {
        Self {
            inner: Arc::new(SinkInner {
                run_id: RunId::new("noop"),
                started_at: Instant::now(),
                next_sequence: AtomicU64::new(1),
                dropped_progress: AtomicU64::new(0),
                dropped_events: AtomicU64::new(0),
                tx: None,
            }),
        }
    }

    /// Returns the run identifier associated with this sink.
    #[must_use]
    pub fn run_id(&self) -> &RunId {
        &self.inner.run_id
    }

    /// Returns the total number of progress events dropped due to channel backpressure.
    #[must_use]
    pub fn dropped_progress_count(&self) -> u64 {
        self.inner.dropped_progress.load(Ordering::Relaxed)
    }

    /// Returns the total number of non-progress events lost to backpressure or closure.
    ///
    /// A non-zero value means the delivered stream is incomplete. Critical outcomes are
    /// still carried by the authoritative run artefacts, so loss degrades presentation
    /// detail rather than the final state.
    #[must_use]
    pub fn dropped_event_count(&self) -> u64 {
        self.inner.dropped_events.load(Ordering::Relaxed)
    }

    /// Emits an event immediately without awaiting.
    ///
    /// If the bounded channel is full:
    /// - Coalescable progress events increment `dropped_progress_events` and return `false`.
    /// - Critical events also attempt `try_send` and return `false` if full in synchronous contexts.
    #[allow(clippy::must_use_candidate)]
    pub fn emit(&self, context: EventContext, payload: DiagnosticEventPayload) -> bool {
        let Some(tx) = &self.inner.tx else {
            return false;
        };
        let is_progress = payload.is_coalescable_progress();
        let event = self.build_event(context, payload);
        match tx.try_send(event) {
            Ok(()) => true,
            Err(mpsc::error::TrySendError::Full(_)) => {
                if is_progress {
                    self.inner.dropped_progress.fetch_add(1, Ordering::Relaxed);
                } else {
                    self.inner.dropped_events.fetch_add(1, Ordering::Relaxed);
                }
                false
            }
            Err(mpsc::error::TrySendError::Closed(_)) => {
                if !is_progress {
                    self.inner.dropped_events.fetch_add(1, Ordering::Relaxed);
                }
                false
            }
        }
    }

    /// Emits an event from an asynchronous context.
    ///
    /// Coalescable progress events use non-blocking `try_send` so diagnostic workers
    /// never stall on UI rendering. Critical lifecycle events await channel capacity
    /// up to 50 ms so findings and state transitions are preserved under burst load
    /// without risking a permanent engine deadlock.
    pub async fn emit_async(&self, context: EventContext, payload: DiagnosticEventPayload) -> bool {
        let Some(tx) = &self.inner.tx else {
            return false;
        };
        if payload.is_coalescable_progress() {
            return self.emit(context, payload);
        }
        let event = self.build_event(context, payload);
        match tx.try_send(event) {
            Ok(()) => true,
            Err(mpsc::error::TrySendError::Full(event)) => {
                let delivered =
                    tokio::time::timeout(std::time::Duration::from_millis(50), tx.send(event))
                        .await
                        .is_ok_and(|res| res.is_ok());
                if !delivered {
                    self.inner.dropped_events.fetch_add(1, Ordering::Relaxed);
                }
                delivered
            }
            Err(mpsc::error::TrySendError::Closed(_)) => {
                self.inner.dropped_events.fetch_add(1, Ordering::Relaxed);
                false
            }
        }
    }

    /// Bridges an existing [`InvestigationEvent`] into the unified diagnostic event stream.
    #[allow(clippy::too_many_lines)]
    pub fn emit_investigation_event(&self, target: &str, event: &InvestigationEvent) {
        let base_ctx = EventContext::new().with_target(target);
        match event {
            InvestigationEvent::InvestigationStarted {
                target: t,
                investigation_id: _,
            } => {
                self.emit(
                    base_ctx.with_target(t.clone()),
                    DiagnosticEventPayload::RunStarted {
                        mode: DiagnosticRunMode::AgenticInvestigation,
                        target: t.clone(),
                    },
                );
            }
            InvestigationEvent::ScopeEstablished { .. } => {}
            InvestigationEvent::SpecialistActivated { dwarf_id, focus } => {
                self.emit(
                    base_ctx.with_dwarf(*dwarf_id),
                    DiagnosticEventPayload::SpecialistActivated {
                        dwarf: *dwarf_id,
                        focus: focus.clone(),
                    },
                );
            }
            InvestigationEvent::ToolRequested { tool_id } => {
                self.emit(
                    base_ctx.with_operation(tool_id.clone()),
                    DiagnosticEventPayload::ToolRequested {
                        tool_id: tool_id.clone(),
                    },
                );
            }
            InvestigationEvent::ToolAuthorised { tool_id } => {
                self.emit(
                    base_ctx.with_operation(tool_id.clone()),
                    DiagnosticEventPayload::ToolAuthorised {
                        tool_id: tool_id.clone(),
                    },
                );
            }
            InvestigationEvent::ToolRejected { tool_id, reason } => {
                self.emit(
                    base_ctx.with_operation(tool_id.clone()),
                    DiagnosticEventPayload::ToolRejected {
                        tool_id: tool_id.clone(),
                        reason: reason.clone(),
                    },
                );
            }
            InvestigationEvent::ToolCompleted { tool_id, succeeded } => {
                self.emit(
                    base_ctx.with_operation(tool_id.clone()),
                    DiagnosticEventPayload::ToolCompleted {
                        tool_id: tool_id.clone(),
                        succeeded: *succeeded,
                        summary: if *succeeded {
                            "Tool execution completed".to_owned()
                        } else {
                            "Tool execution failed".to_owned()
                        },
                    },
                );
            }
            InvestigationEvent::HypothesisProposed {
                hypothesis_id,
                originating_rule,
            } => {
                self.emit(
                    base_ctx.with_dwarf(DwarfId::Kommandant),
                    DiagnosticEventPayload::HypothesisProposed {
                        hypothesis_id: hypothesis_id.clone(),
                        originating_rule: originating_rule.clone(),
                        proposed_explanation: String::new(),
                        requested_tool: String::new(),
                    },
                );
            }
            InvestigationEvent::HypothesisEvaluated {
                hypothesis_id,
                status,
            } => {
                self.emit(
                    base_ctx.with_dwarf(DwarfId::Kommandant),
                    DiagnosticEventPayload::HypothesisEvaluated {
                        hypothesis_id: hypothesis_id.clone(),
                        status: status.clone(),
                        summary: None,
                    },
                );
            }
            InvestigationEvent::InvestigationCompleted { investigation_id } => {
                self.emit(
                    base_ctx,
                    DiagnosticEventPayload::RunCompleted {
                        summary: format!("Investigation {investigation_id} completed"),
                    },
                );
            }
            InvestigationEvent::InvestigationPartiallyCompleted {
                investigation_id: _,
                reason,
            } => {
                self.emit(
                    base_ctx,
                    DiagnosticEventPayload::RunPartiallyCompleted {
                        reason: reason.clone(),
                    },
                );
            }
        }
    }

    fn build_event(
        &self,
        context: EventContext,
        payload: DiagnosticEventPayload,
    ) -> DiagnosticEvent {
        let sequence = self.inner.next_sequence.fetch_add(1, Ordering::Relaxed);
        let elapsed_ms =
            u64::try_from(self.inner.started_at.elapsed().as_millis()).unwrap_or(u64::MAX);
        let dropped_progress_events = self.inner.dropped_progress.load(Ordering::Relaxed);
        let dropped_events = self.inner.dropped_events.load(Ordering::Relaxed);
        DiagnosticEvent {
            run_id: self.inner.run_id.clone(),
            sequence,
            elapsed_ms,
            dropped_progress_events,
            dropped_events,
            context,
            payload,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn noop_sink_discards_without_error() {
        let sink = DiagnosticEventSink::noop();
        assert!(!sink.emit(
            EventContext::new(),
            DiagnosticEventPayload::CollectionStarted {
                collector: CollectorId::Http,
            }
        ));
        assert_eq!(sink.dropped_progress_count(), 0);
    }

    #[test]
    fn bounded_sink_assigns_monotonic_sequences_and_tracks_dropped_progress() {
        let (sink, mut rx) = DiagnosticEventSink::bounded("run-42", 2);

        assert!(sink.emit(
            EventContext::new().with_target("https://example.org"),
            DiagnosticEventPayload::RunStarted {
                mode: DiagnosticRunMode::DeterministicCheck,
                target: "https://example.org".to_owned(),
            }
        ));
        assert!(sink.emit(
            EventContext::new().with_collector(CollectorId::Http),
            DiagnosticEventPayload::CollectionProgress {
                collector: CollectorId::Http,
                completed_units: 1,
                total_units: Some(2),
                detail: "fetching root".to_owned(),
            }
        ));

        // Channel capacity (2) is now full. Next progress event must be dropped and counted.
        assert!(!sink.emit(
            EventContext::new().with_collector(CollectorId::Http),
            DiagnosticEventPayload::CollectionProgress {
                collector: CollectorId::Http,
                completed_units: 2,
                total_units: Some(2),
                detail: "reading body".to_owned(),
            }
        ));
        assert_eq!(sink.dropped_progress_count(), 1);

        let first = rx.try_recv().expect("first event");
        assert_eq!(first.sequence, 1);
        assert_eq!(first.run_id, RunId::new("run-42"));

        let second = rx.try_recv().expect("second event");
        assert_eq!(second.sequence, 2);

        // Now capacity is available again; next event reflects dropped_progress_events = 1.
        assert!(sink.emit(
            EventContext::new().with_collector(CollectorId::Http),
            DiagnosticEventPayload::CollectionCompleted {
                collector: CollectorId::Http,
                partial: false,
                warnings: Vec::new(),
            }
        ));
        let third = rx.try_recv().expect("third event");
        assert_eq!(third.sequence, 4);
        assert_eq!(third.dropped_progress_events, 1);
        assert_eq!(third.dropped_events, 0);
    }

    #[test]
    fn critical_event_loss_is_counted_separately_from_progress_loss() {
        let (sink, mut rx) = DiagnosticEventSink::bounded("run-7", 1);

        assert!(sink.emit(
            EventContext::new(),
            DiagnosticEventPayload::CollectionStarted {
                collector: CollectorId::Http,
            }
        ));

        // The channel is full: a non-progress event must be counted as lost, not ignored.
        assert!(!sink.emit(
            EventContext::new(),
            DiagnosticEventPayload::AnalysisStarted {
                dwarf: crate::brigade::DwarfId::Netz,
            }
        ));
        assert_eq!(sink.dropped_event_count(), 1);
        assert_eq!(sink.dropped_progress_count(), 0);

        let first = rx.try_recv().expect("first event");
        assert_eq!(first.dropped_events, 0);

        // A later delivered event reports the cumulative loss so consumers can detect gaps.
        assert!(sink.emit(
            EventContext::new(),
            DiagnosticEventPayload::CollectionCompleted {
                collector: CollectorId::Http,
                partial: false,
                warnings: Vec::new(),
            }
        ));
        let second = rx.try_recv().expect("second event");
        assert_eq!(second.sequence, 3);
        assert_eq!(second.dropped_events, 1);
    }
}
