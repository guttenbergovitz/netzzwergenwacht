//! `NetzZwergenWacht` core library.
//!
//! Separates validated domain contracts ([`domain`]), bounded external
//! evidence collection ([`collection`]), and deterministic analysers
//! ([`analysis`]).

pub mod analysis;
pub mod collection;
pub mod domain;
