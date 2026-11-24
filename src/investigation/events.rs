//! Live investigation event model reflecting actual execution transitions.

use serde::{Deserialize, Serialize};

use crate::brigade::DwarfId;

/// Real-time execution event emitted during an investigation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "event", rename_all = "snake_case")]
pub enum InvestigationEvent {
    /// Investigation started for a target and objective.
    InvestigationStarted {
        /// Investigation identifier.
        investigation_id: String,
        /// Target URL.
        target: String,
    },
    /// Investigation scope and policy validated.
    ScopeEstablished {
        /// Primary authorised origin.
        origin: String,
    },
    /// A specialist dwarf contributed observations.
    SpecialistActivated {
        /// Specialist dwarf identity.
        dwarf_id: DwarfId,
        /// Analytical focus.
        focus: String,
    },
    /// A typed diagnostic tool was requested.
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
    },
    /// A diagnostic hypothesis was proposed.
    HypothesisProposed {
        /// Hypothesis identifier.
        hypothesis_id: String,
        /// Originating rule identifier.
        originating_rule: String,
    },
    /// A diagnostic hypothesis was evaluated against collected evidence.
    HypothesisEvaluated {
        /// Hypothesis identifier.
        hypothesis_id: String,
        /// Evaluation outcome.
        status: String,
    },
    /// Investigation completed within budget.
    InvestigationCompleted {
        /// Investigation identifier.
        investigation_id: String,
    },
    /// Investigation completed with partial evidence or budget exhaustion.
    InvestigationPartiallyCompleted {
        /// Investigation identifier.
        investigation_id: String,
        /// Reason for partial completion.
        reason: String,
    },
}
