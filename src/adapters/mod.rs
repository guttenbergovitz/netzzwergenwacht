//! Bounded external tool and browser adapters.
//!
//! External measurement engines (such as Lighthouse) run as isolated,
//! timeout-bounded subprocesses and record tool version and execution status.

pub mod lighthouse;
